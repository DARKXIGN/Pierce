#include "coord/service.hpp"

#include <openssl/rand.h>

#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <optional>

#include "coord/timing.hpp"

namespace coord {

using pierce::coord::AgentMsg;
using pierce::coord::Candidates;
using pierce::coord::CoordMsg;
using Clock = std::chrono::steady_clock;

// One connected agent, i.e. one open stream.
struct Service::Peer {
  grpc::ServerReaderWriter<CoordMsg, AgentMsg>* stream = nullptr;
  // Guarded by Service::mu_.
  std::string id, peer_id;
  std::optional<Candidates> candidates;
  bool paired = false;

  // A gRPC stream allows one writer at a time, and must not be written after its handler has
  // returned. write_mu serialises writers; alive turns false when the handler exits. It is atomic
  // because wait_pong() also reads it, under a different mutex.
  std::mutex write_mu;
  std::atomic<bool> alive = true;
  bool write(const CoordMsg& m) {
    std::lock_guard lock(write_mu);
    return alive && stream->Write(m);
  }

  // Pongs by nonce, with the time they arrived. Filled by the handler, read by the pairing thread.
  std::mutex pong_mu;
  std::condition_variable pong_cv;
  std::map<std::uint64_t, Clock::time_point> pongs;
  std::optional<Clock::time_point> wait_pong(std::uint64_t nonce, Clock::time_point deadline) {
    std::unique_lock lock(pong_mu);
    pong_cv.wait_until(lock, deadline, [&] { return pongs.contains(nonce) || !alive; });
    if (auto it = pongs.find(nonce); it != pongs.end()) return it->second;
    return std::nullopt;
  }
};

namespace {

std::string candidates_text(const Candidates& c) {
  std::string out;
  for (const auto& cand : c.candidates()) {
    const auto& ip = cand.ipv4();
    if (ip.size() != 4) continue;
    char buf[48];
    std::snprintf(buf, sizeof buf, "%s%s %u.%u.%u.%u:%u", out.empty() ? "" : ", ",
                  cand.type() == pierce::coord::Candidate::SRFLX ? "srflx" : "host",
                  std::uint8_t(ip[0]), std::uint8_t(ip[1]), std::uint8_t(ip[2]),
                  std::uint8_t(ip[3]), cand.port());
    out += buf;
  }
  return out;
}

std::uint64_t random_nonce() {
  std::uint64_t n = 0;
  RAND_bytes(reinterpret_cast<unsigned char*>(&n), sizeof n);
  return n;
}

}  // namespace

Service::~Service() {
  std::lock_guard lock(mu_);
  threads_.clear();  // jthread joins on destruction
}

grpc::Status Service::Session(grpc::ServerContext*,
                              grpc::ServerReaderWriter<CoordMsg, AgentMsg>* stream) {
  auto peer = std::make_shared<Peer>();
  peer->stream = stream;
  AgentMsg m;
  while (stream->Read(&m)) {
    switch (m.msg_case()) {
      case AgentMsg::kRegister: {
        std::lock_guard lock(mu_);
        peer->id = m.register_().node_id();
        peer->peer_id = m.register_().peer_id();
        // A newer stream for the same node replaces the old one (e.g. the agent restarted).
        peers_[peer->id] = peer;
        db_.upsert_node(peer->id, peer->peer_id);
        break;
      }
      case AgentMsg::kCandidates: {
        {
          std::lock_guard lock(mu_);
          if (peer->id.empty()) break;  // must register first
          peer->candidates = m.candidates();
        }
        db_.set_candidates(peer->id, candidates_text(m.candidates()));
        try_pair(peer);
        break;
      }
      case AgentMsg::kPong: {
        std::lock_guard lock(peer->pong_mu);
        peer->pongs[m.pong().nonce()] = Clock::now();
        peer->pong_cv.notify_all();
        break;
      }
      case AgentMsg::MSG_NOT_SET:
        break;
    }
  }
  // Stream closed: stop writers, wake anyone waiting for a pong, forget the peer.
  {
    std::lock_guard lock(peer->write_mu);
    peer->alive = false;
  }
  {
    std::lock_guard lock(peer->pong_mu);
    peer->pong_cv.notify_all();
  }
  std::lock_guard lock(mu_);
  if (auto it = peers_.find(peer->id); it != peers_.end() && it->second == peer) peers_.erase(it);
  return grpc::Status::OK;
}

void Service::try_pair(const std::shared_ptr<Peer>& peer) {
  std::lock_guard lock(mu_);
  if (peer->paired || !peer->candidates) return;
  auto it = peers_.find(peer->peer_id);
  if (it == peers_.end()) return;  // the other side is not here yet; it will call try_pair
  auto other = it->second;
  if (other->paired || !other->candidates || other->peer_id != peer->id) return;
  peer->paired = other->paired = true;
  // Measuring RTT takes a few round trips; do it off the gRPC handler thread.
  threads_.emplace_back([this, peer, other] { run_pairing(peer, other); });
}

void Service::run_pairing(std::shared_ptr<Peer> a, std::shared_ptr<Peer> b) {
  // RTT to each peer over its signaling stream: send Ping to both at once, time the Pongs.
  std::optional<Clock::duration> rtt_a, rtt_b;
  for (int i = 0; i < opt_.pings; ++i) {
    CoordMsg ping;
    ping.mutable_ping()->set_nonce(random_nonce());
    const auto nonce = ping.ping().nonce();
    const auto sent = Clock::now();
    a->write(ping);
    b->write(ping);
    const auto deadline = sent + opt_.pong_timeout;
    if (auto t = a->wait_pong(nonce, deadline)) rtt_a = std::min(rtt_a.value_or(*t - sent), *t - sent);
    if (auto t = b->wait_pong(nonce, deadline)) rtt_b = std::min(rtt_b.value_or(*t - sent), *t - sent);
  }
  if (!rtt_a || !rtt_b) {
    std::fprintf(stderr, "pair %s<->%s: no pong, giving up\n", a->id.c_str(), b->id.c_str());
    return;
  }
  using std::chrono::duration_cast;
  using ms = std::chrono::milliseconds;
  const auto ra = duration_cast<ms>(*rtt_a), rb = duration_cast<ms>(*rtt_b);
  db_.set_rtt(a->id, std::chrono::duration<double, std::milli>(*rtt_a).count());
  db_.set_rtt(b->id, std::chrono::duration<double, std::milli>(*rtt_b).count());
  const auto delays = punch_delays(ra, rb, opt_.margin);

  CoordMsg key;
  std::string k(32, '\0');
  RAND_bytes(reinterpret_cast<unsigned char*>(k.data()), static_cast<int>(k.size()));
  key.mutable_session_key()->set_key(k);

  auto send_to = [&](Peer& to, const Peer& from, ms delay) {
    CoordMsg cands;
    *cands.mutable_peer_candidates() = *from.candidates;
    CoordMsg punch;
    punch.mutable_punch_in()->set_delay_ms(static_cast<std::uint32_t>(delay.count()));
    to.write(cands);
    to.write(key);
    to.write(punch);
  };
  // Candidates and key first, so the PunchIn messages, sent last, leave as close together as
  // possible.
  send_to(*a, *b, delays.a);
  send_to(*b, *a, delays.b);
  if (opt_.verbose)
    std::fprintf(stderr, "pair %s<->%s: rtt %lld/%lld ms, punch in %lld/%lld ms\n", a->id.c_str(),
                 b->id.c_str(), static_cast<long long>(ra.count()),
                 static_cast<long long>(rb.count()), static_cast<long long>(delays.a.count()),
                 static_cast<long long>(delays.b.count()));
}

}  // namespace coord
