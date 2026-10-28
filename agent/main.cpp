// pierce-agent: one direct-connection attempt to a peer (stage 2: probes only, no data plane yet).
//
//   pierce-agent --coord 203.0.113.10:50051 --stun 203.0.113.10:3478 --id A --peer B
//                [--timeout-ms 3000] [--signal-timeout-ms 5000] [--interval-ms 20]
//                [--hold SEC] [--keepalive-ms 25000]
//
// Prints one line to stdout:  success,time_to_connect_ms,probes_sent,path,remote
//   e.g. 1,142,7,direct,203.0.113.2:41000      or      0,,150,none,
// time_to_connect_ms runs from sending Register (start of signaling) to the first authenticated
// probe response. With --hold, stays connected for SEC seconds sending keepalives, which needs no
// coordination server, and reports "keepalive sent=N answered=M" on stderr.
#include <grpcpp/grpcpp.h>

#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>

#include "agent/candidates.hpp"
#include "agent/punch.hpp"
#include "coord.grpc.pb.h"
#include "stun/client.hpp"
#include "stun/udp.hpp"

namespace {

using agent::Candidate;
using agent::CandidateType;
using agent::Clock;
namespace pb = pierce::coord;

[[noreturn]] void usage() {
  std::fputs(
      "usage: pierce-agent --coord HOST:PORT --stun IP:PORT --id ID --peer ID [--timeout-ms N]\n"
      "                    [--signal-timeout-ms N] [--interval-ms N] [--hold SEC] [--keepalive-ms N]\n",
      stderr);
  std::exit(2);
}

pb::Candidate to_proto(const Candidate& c) {
  pb::Candidate p;
  p.set_type(c.type == CandidateType::ServerReflexive ? pb::Candidate::SRFLX : pb::Candidate::HOST);
  p.set_ipv4(std::string(c.ep.ipv4.begin(), c.ep.ipv4.end()));
  p.set_port(c.ep.port);
  p.set_priority(c.priority);
  return p;
}

std::optional<Candidate> from_proto(const pb::Candidate& p) {
  if (p.ipv4().size() != 4 || p.port() == 0 || p.port() > 65535) return std::nullopt;
  Candidate c;
  c.type = p.type() == pb::Candidate::SRFLX ? CandidateType::ServerReflexive : CandidateType::Host;
  std::copy(p.ipv4().begin(), p.ipv4().end(), c.ep.ipv4.begin());
  c.ep.port = static_cast<std::uint16_t>(p.port());
  c.priority = p.priority();
  return c;
}

// What the signaling reader thread hands to the main thread.
struct Signal {
  std::mutex mu;
  std::condition_variable cv;
  std::vector<Candidate> peer_candidates;
  probe::Key key;
  std::optional<std::chrono::milliseconds> punch_delay;
  Clock::time_point punch_received{};
  bool closed = false;
};

}  // namespace

int main(int argc, char** argv) try {
  std::string coord_addr, id, peer;
  std::optional<stun::Endpoint> stun_server;
  agent::PunchOptions popt;
  auto signal_timeout = std::chrono::milliseconds(5000);
  int hold_s = 0;
  auto keepalive = std::chrono::milliseconds(25000);
  for (int i = 1; i < argc; ++i) {
    std::string_view a = argv[i];
    auto value = [&] {
      if (i + 1 >= argc) usage();
      return std::string(argv[++i]);
    };
    auto ms = [&] { return std::chrono::milliseconds(std::atoi(value().c_str())); };
    if (a == "--coord") coord_addr = value();
    else if (a == "--stun") stun_server = stun::parse_endpoint(value());
    else if (a == "--id") id = value();
    else if (a == "--peer") peer = value();
    else if (a == "--timeout-ms") popt.timeout = ms();
    else if (a == "--signal-timeout-ms") signal_timeout = ms();
    else if (a == "--interval-ms") popt.interval = ms();
    else if (a == "--hold") hold_s = std::atoi(value().c_str());
    else if (a == "--keepalive-ms") keepalive = ms();
    else usage();
  }
  if (coord_addr.empty() || !stun_server || id.empty() || peer.empty() || id == peer) usage();

  auto fail = [](int probes) {
    std::printf("0,,%d,none,\n", probes);
    return 0;
  };

  // 1. One UDP socket for everything: STUN, probes (and WireGuard later). NAT mappings belong to
  //    a socket, so the address STUN reports is only useful if the probes leave from it too.
  stun::UdpSocket sock;
  std::vector<Candidate> mine = agent::host_candidates(sock.local_endpoint().port);
  if (auto r = stun::binding(sock, *stun_server, 0, std::chrono::milliseconds(200), 3))
    mine.push_back({CandidateType::ServerReflexive, *r->xor_mapped,
                    agent::priority(CandidateType::ServerReflexive)});
  else
    std::fputs("pierce-agent: no STUN response; host candidates only\n", stderr);

  // 2. Signaling.
  // Never go through an HTTP proxy from the environment (http_proxy etc.): the coordination
  // server is reached directly, like the peer.
  grpc::ChannelArguments args;
  args.SetInt(GRPC_ARG_ENABLE_HTTP_PROXY, 0);
  auto channel =
      grpc::CreateCustomChannel(coord_addr, grpc::InsecureChannelCredentials(), args);
  if (!channel->WaitForConnected(std::chrono::system_clock::now() + signal_timeout)) {
    std::fprintf(stderr, "pierce-agent: cannot reach coordination server %s\n", coord_addr.c_str());
    return fail(0);
  }
  auto stub = pb::Coord::NewStub(channel);
  grpc::ClientContext ctx;
  auto stream = stub->Session(&ctx);

  const auto signaling_start = Clock::now();
  pb::AgentMsg reg;
  reg.mutable_register_()->set_node_id(id);
  reg.mutable_register_()->set_peer_id(peer);
  pb::AgentMsg cands;
  for (const auto& c : mine) *cands.mutable_candidates()->add_candidates() = to_proto(c);
  stream->Write(reg);
  stream->Write(cands);

  // From here on only the reader thread writes to the stream (Pongs), so writes never overlap.
  Signal sig;
  std::thread reader([&] {
    pb::CoordMsg m;
    while (stream->Read(&m)) {
      if (m.has_ping()) {
        pb::AgentMsg pong;
        pong.mutable_pong()->set_nonce(m.ping().nonce());
        stream->Write(pong);
        continue;
      }
      std::lock_guard lock(sig.mu);
      if (m.has_peer_candidates()) {
        sig.peer_candidates.clear();
        for (const auto& p : m.peer_candidates().candidates())
          if (auto c = from_proto(p)) sig.peer_candidates.push_back(*c);
      } else if (m.has_session_key()) {
        sig.key.assign(m.session_key().key().begin(), m.session_key().key().end());
      } else if (m.has_punch_in()) {
        sig.punch_delay = std::chrono::milliseconds(m.punch_in().delay_ms());
        sig.punch_received = Clock::now();
      }
      sig.cv.notify_all();
    }
    // The server went away (or we cancelled). A connected agent does not care.
    std::lock_guard lock(sig.mu);
    sig.closed = true;
    sig.cv.notify_all();
  });
  auto stop_signaling = [&] {
    ctx.TryCancel();
    reader.join();
  };

  std::vector<Candidate> peer_cands;
  probe::Key key;
  Clock::time_point punch_at;
  {
    std::unique_lock lock(sig.mu);
    const bool got = sig.cv.wait_for(lock, signal_timeout, [&] {
      return sig.closed || (sig.punch_delay && !sig.key.empty());
    });
    if (!got || !sig.punch_delay || sig.key.empty() || sig.peer_candidates.empty()) {
      lock.unlock();
      std::fputs("pierce-agent: no PunchIn from the coordination server\n", stderr);
      stop_signaling();
      return fail(0);
    }
    peer_cands = sig.peer_candidates;
    key = sig.key;
    punch_at = sig.punch_received + *sig.punch_delay;
  }

  // 3. Punch: wait for the agreed moment, then probe.
  std::this_thread::sleep_until(punch_at);
  agent::Puncher puncher(sock, key, peer_cands);
  const auto res = puncher.connect(popt);
  if (!res.success) {
    stop_signaling();
    return fail(puncher.probes_sent());
  }
  const auto ttc =
      std::chrono::duration_cast<std::chrono::milliseconds>(res.connected_at - signaling_start);
  std::printf("1,%lld,%d,direct,%s\n", static_cast<long long>(ttc.count()), puncher.probes_sent(),
              stun::to_string(*res.path).c_str());
  std::fflush(stdout);

  // 4. Optionally stay connected. Keepalives are peer to peer: the coordination server may die.
  if (hold_s > 0) {
    std::fputs("connected\n", stderr);
    const auto stats = puncher.hold(*res.path, std::chrono::seconds(hold_s), keepalive);
    std::fprintf(stderr, "keepalive sent=%d answered=%d\n", stats.sent, stats.answered);
  }
  stop_signaling();
  return 0;
} catch (const std::exception& e) {
  std::fprintf(stderr, "pierce-agent: %s\n", e.what());
  std::printf("0,,0,none,\n");
  return 1;
}
