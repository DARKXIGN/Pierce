// pierce-agent: one direct-connection attempt to a peer (stage 2: probes only, no data plane yet).
//
//   pierce-agent --coord 203.0.113.10:50051 --stun 203.0.113.10:3478 --id A --peer B
//                [--stun-alt-ip 203.0.113.11] [--stun-alt-port 3479] [--predict-window 32]
//                [--timeout-ms 3000] [--signal-timeout-ms 5000] [--interval-ms 20]
//                [--hold SEC] [--keepalive-ms 25000]
//
// With --stun-alt-ip, the agent also asks the STUN server's other IP and other port for its public
// port, from the same socket, to learn how its NAT maps ports (predict.hpp). If the peer's NAT
// turns out to be sequential, the agent adds up to --predict-window predicted ports to probe.
//
// Prints one line to stdout:  success,time_to_connect_ms,probes_sent,path,remote
//   e.g. 1,142,7,direct,203.0.113.2:41000      or      0,,150,none,
// time_to_connect_ms runs from sending Register (start of signaling) to the first authenticated
// probe response. With --hold, stays connected for SEC seconds sending keepalives, which needs no
// coordination server, and reports "keepalive sent=N answered=M" on stderr.
#include <grpcpp/grpcpp.h>

#include <algorithm>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>

#include "agent/candidates.hpp"
#include "agent/predict.hpp"
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
      "usage: pierce-agent --coord HOST:PORT --stun IP:PORT --id ID --peer ID [--stun-alt-ip IP]\n"
      "                    [--stun-alt-port N] [--predict-window N] [--timeout-ms N]\n"
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

pb::NatInfo to_proto(const agent::NatInfo& n) {
  pb::NatInfo p;
  switch (n.mapping) {
    case agent::Mapping::Unknown: p.set_mapping(pb::NatInfo::UNKNOWN); break;
    case agent::Mapping::EndpointIndependent: p.set_mapping(pb::NatInfo::ENDPOINT_INDEPENDENT); break;
    case agent::Mapping::SymmetricRandom: p.set_mapping(pb::NatInfo::SYMMETRIC_RANDOM); break;
    case agent::Mapping::SymmetricSequential: p.set_mapping(pb::NatInfo::SYMMETRIC_SEQUENTIAL); break;
  }
  p.set_last_port(n.last_port);
  p.set_step(n.step);
  return p;
}

agent::NatInfo from_proto(const pb::NatInfo& p) {
  agent::NatInfo n;
  switch (p.mapping()) {
    case pb::NatInfo::ENDPOINT_INDEPENDENT: n.mapping = agent::Mapping::EndpointIndependent; break;
    case pb::NatInfo::SYMMETRIC_RANDOM: n.mapping = agent::Mapping::SymmetricRandom; break;
    case pb::NatInfo::SYMMETRIC_SEQUENTIAL: n.mapping = agent::Mapping::SymmetricSequential; break;
    default: n.mapping = agent::Mapping::Unknown; break;
  }
  n.last_port = p.last_port() <= 65535 ? static_cast<std::uint16_t>(p.last_port()) : 0;
  n.step = p.step();
  return n;
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
  agent::NatInfo peer_nat;
  probe::Key key;
  std::optional<std::chrono::milliseconds> punch_delay;
  Clock::time_point punch_received{};
  bool closed = false;
};

}  // namespace

int main(int argc, char** argv) try {
  std::string coord_addr, id, peer;
  std::optional<stun::Endpoint> stun_server;
  std::optional<std::array<std::uint8_t, 4>> stun_alt_ip;
  std::uint16_t stun_alt_port = 3479;
  int predict_window = 32;
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
    else if (a == "--stun-alt-ip") { stun_alt_ip = stun::parse_ipv4(value()); if (!stun_alt_ip) usage(); }
    else if (a == "--stun-alt-port") stun_alt_port = static_cast<std::uint16_t>(std::atoi(value().c_str()));
    else if (a == "--predict-window") predict_window = std::atoi(value().c_str());
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
  auto ask = [&](const stun::Endpoint& to) -> std::optional<stun::Endpoint> {
    if (auto r = stun::binding(sock, to, 0, std::chrono::milliseconds(200), 3)) return r->xor_mapped;
    return std::nullopt;
  };
  agent::NatInfo my_nat;
  if (auto srflx = ask(*stun_server)) {
    mine.push_back({CandidateType::ServerReflexive, *srflx,
                    agent::priority(CandidateType::ServerReflexive)});
    // Same socket, two more destinations: does the public port change, and how?
    if (stun_alt_ip) {
      auto p2 = ask({*stun_alt_ip, stun_server->port});
      auto p3 = ask({stun_server->ipv4, stun_alt_port});
      if (p2 && p3) my_nat = agent::characterize(srflx->port, p2->port, p3->port);
    }
  } else {
    std::fputs("pierce-agent: no STUN response; host candidates only\n", stderr);
  }

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
  *cands.mutable_candidates()->mutable_nat() = to_proto(my_nat);
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
        sig.peer_nat = from_proto(m.peer_candidates().nat());
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
  agent::NatInfo peer_nat;
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
    peer_nat = sig.peer_nat;
    key = sig.key;
    punch_at = sig.punch_received + *sig.punch_delay;
  }

  // Peer behind a sequential NAT: add predicted ports on its public IP (from its srflx candidate).
  auto peer_srflx = std::find_if(peer_cands.begin(), peer_cands.end(), [](const Candidate& c) {
    return c.type == CandidateType::ServerReflexive;
  });
  if (peer_srflx != peer_cands.end()) {
    const bool we_seq = my_nat.mapping == agent::Mapping::SymmetricSequential;
    auto predicted = agent::predicted_candidates(peer_srflx->ep.ipv4, peer_nat, we_seq,
                                                 mine.size(), predict_window);
    peer_cands.insert(peer_cands.end(), predicted.begin(), predicted.end());
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
