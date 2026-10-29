// pierce-agent: one direct-connection attempt to a peer (stage 2: probes only, no data plane yet).
//
//   pierce-agent --coord 203.0.113.10:50051 --stun 203.0.113.10:3478 --id A --peer B
//                [--stun-alt-ip 203.0.113.11] [--stun-alt-port 3479] [--predict-window 32]
//                [--birthday 256] [--retry-direct-ms 30000]
//                [--tun pierce0 --wg-key PRIVATE --wg-peer PUBLIC]
//                [--timeout-ms 3000] [--signal-timeout-ms 5000] [--interval-ms 20]
//                [--hold SEC] [--keepalive-ms 25000]
//
// With --stun-alt-ip, the agent also asks the STUN server's other IP and other port for its public
// port, from the same socket, to learn how its NAT maps ports (predict.hpp). If the peer's NAT
// turns out to be sequential, the agent adds up to --predict-window predicted ports to probe.
// If one side's NAT maps randomly and the other's is a cone, they do birthday probing: the random
// side probes from --birthday extra sockets, the cone side guesses as many ports (0 = off).
//
// Prints one line to stdout:  direct,time_to_connect_ms,probes_sent,path,remote
//   1,142,7,direct,203.0.113.2:41000     connected directly
//   0,3071,160,relay,203.0.113.10:3480   direct failed, connected through the relay
//   0,4210,180,relay-tls,127.0.0.1:41000 same, over TCP/TLS (UDP to the relay got no answer)
//   0,,150,none,                         neither
// time_to_connect_ms runs from sending Register (start of signaling) to the first authenticated
// probe response, over whichever path won. The direct attempt gets --timeout-ms (3 s); if it
// fails and the coordination server granted a relay, the agent binds to it and probes through it.
// While relayed and holding (--hold), it asks for a new direct attempt every --retry-direct-ms
// (0 = never) and reports "upgrade_ms=N" on stderr if one succeeds (time since the relay
// connected).
// With --tun (stage 4) the agent runs the WireGuard data plane after connecting instead of probe
// keepalives: TUN device <-> BoringTun <-> the socket and path the connection was made on, for
// --hold seconds (0 = until killed). Keys are base64 (pierce-wgkey genkey / pubkey); the peer's
// public key is exchanged in advance, never through the coordination server. With --hold, stays connected for SEC seconds sending keepalives, which needs no
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
#include "agent/relay_client.hpp"
#include "agent/tls_relay.hpp"
#include "coord.grpc.pb.h"
#include "stun/client.hpp"
#include "stun/udp.hpp"
#ifdef PIERCE_HAVE_WIREGUARD
#include "wg/dataplane.hpp"
#include "wg/tun.hpp"
#include "wg/tunnel.hpp"
#endif

namespace {

using agent::Candidate;
using agent::CandidateType;
using agent::Clock;
namespace pb = pierce::coord;

[[noreturn]] void usage() {
  std::fputs(
      "usage: pierce-agent --coord HOST:PORT --stun IP:PORT --id ID --peer ID [--stun-alt-ip IP]\n"
      "                    [--stun-alt-port N] [--predict-window N] [--birthday N] [--timeout-ms N]\n"
      "                    [--signal-timeout-ms N] [--interval-ms N] [--hold SEC] [--keepalive-ms N]\n"
      "                    [--retry-direct-ms N] [--tun NAME --wg-key PRIVATE --wg-peer PUBLIC]\n",
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
  std::vector<stun::Endpoint> relays;  // from RelayList, to measure
  bool relays_received = false;
  std::uint64_t punch_seq = 0;  // counts PunchIn messages, so a retry can wait for a new one
  std::optional<stun::Endpoint> relay;  // from RelayGrant
  std::uint16_t relay_tls_port = 0;
  relay::TokenBytes relay_token{};
  bool closed = false;
};

std::optional<stun::Endpoint> from_proto(const pb::Relay& r) {
  if (r.ipv4().size() != 4 || r.port() == 0 || r.port() > 65535) return std::nullopt;
  stun::Endpoint ep;
  std::copy(r.ipv4().begin(), r.ipv4().end(), ep.ipv4.begin());
  ep.port = static_cast<std::uint16_t>(r.port());
  return ep;
}

}  // namespace

int main(int argc, char** argv) try {
  std::string coord_addr, id, peer;
  std::optional<stun::Endpoint> stun_server;
  std::optional<std::array<std::uint8_t, 4>> stun_alt_ip;
  std::uint16_t stun_alt_port = 3479;
  int predict_window = 32;
  int birthday = 256;
  agent::PunchOptions popt;
  auto signal_timeout = std::chrono::milliseconds(5000);
  int hold_s = 0;
  auto keepalive = std::chrono::milliseconds(25000);
  auto retry_direct = std::chrono::milliseconds(30000);
  std::string tun_name, wg_key, wg_peer;
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
    else if (a == "--birthday") birthday = std::clamp(std::atoi(value().c_str()), 0, 256);
    else if (a == "--id") id = value();
    else if (a == "--peer") peer = value();
    else if (a == "--timeout-ms") popt.timeout = ms();
    else if (a == "--signal-timeout-ms") signal_timeout = ms();
    else if (a == "--interval-ms") popt.interval = ms();
    else if (a == "--hold") hold_s = std::atoi(value().c_str());
    else if (a == "--keepalive-ms") keepalive = ms();
    else if (a == "--retry-direct-ms") retry_direct = ms();
    else if (a == "--tun") tun_name = value();
    else if (a == "--wg-key") wg_key = value();
    else if (a == "--wg-peer") wg_peer = value();
    else usage();
  }
  if (coord_addr.empty() || !stun_server || id.empty() || peer.empty() || id == peer) usage();
  if (!tun_name.empty() && (wg_key.empty() || wg_peer.empty())) usage();
#ifdef PIERCE_HAVE_WIREGUARD
  // Open the TUN device and check the keys before anything else, so a missing permission or a
  // typo in a key fails right away instead of after connecting.
  std::optional<wg::Tun> tun;
  std::optional<wg::Tunnel> tunnel;
  if (!tun_name.empty()) {
    tun.emplace(tun_name);
    const auto ka = std::chrono::duration_cast<std::chrono::seconds>(keepalive).count();
    tunnel.emplace(wg_key, wg_peer, static_cast<std::uint16_t>(std::clamp<long long>(ka, 0, 65535)));
  }
#else
  if (!tun_name.empty()) {
    std::fputs("pierce-agent: built without the WireGuard data plane (no cargo at build time)\n",
               stderr);
    return 2;
  }
#endif

  auto fail = [](int probes) {
    std::printf("0,,%d,none,\n", probes);
    return 0;
  };

  // 1. One UDP socket for everything: STUN, probes (and WireGuard later). NAT mappings belong to
  //    a socket, so the address STUN reports is only useful if the probes leave from it too.
  stun::UdpSocket sock;
  std::vector<Candidate> mine;
  agent::NatInfo my_nat;
  // Gather host and server-reflexive candidates and characterize the NAT's mapping. Run again
  // before each retry of the direct path, because the NAT's mappings may have changed since.
  auto gather = [&] {
    mine = agent::host_candidates(sock.local_endpoint().port, tun_name);
    my_nat = {};
    auto ask = [&](const stun::Endpoint& to) -> std::optional<stun::Endpoint> {
      if (auto r = stun::binding(sock, to, 0, std::chrono::milliseconds(200), 3)) return r->xor_mapped;
      return std::nullopt;
    };
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
  };
  auto candidates_msg = [&] {
    pb::AgentMsg cands;
    for (const auto& c : mine) *cands.mutable_candidates()->add_candidates() = to_proto(c);
    *cands.mutable_candidates()->mutable_nat() = to_proto(my_nat);
    return cands;
  };

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
  stream->Write(reg);

  // A gRPC stream takes one writer at a time: the reader thread writes Pongs, the main thread
  // RelayRtts, so both go through write().
  std::mutex write_mu;
  auto write = [&](const pb::AgentMsg& msg) {
    std::lock_guard lock(write_mu);
    stream->Write(msg);
  };
  Signal sig;
  std::thread reader([&] {
    pb::CoordMsg m;
    while (stream->Read(&m)) {
      if (m.has_ping()) {
        pb::AgentMsg pong;
        pong.mutable_pong()->set_nonce(m.ping().nonce());
        write(pong);
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
        ++sig.punch_seq;
      } else if (m.has_relay_list()) {
        sig.relays.clear();
        for (const auto& r : m.relay_list().relays())
          if (auto ep = from_proto(r)) sig.relays.push_back(*ep);
        sig.relays_received = true;
      } else if (m.has_relay_grant() && m.relay_grant().token().size() == relay::kTokenSize) {
        sig.relay = from_proto(m.relay_grant().relay());
        sig.relay_tls_port = static_cast<std::uint16_t>(m.relay_grant().relay().tls_port());
        std::copy(m.relay_grant().token().begin(), m.relay_grant().token().end(),
                  sig.relay_token.begin());
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

  // What one direct attempt needs from signaling.
  struct Plan {
    std::vector<Candidate> peer_cands;
    agent::NatInfo peer_nat;
    probe::Key key;
    Clock::time_point punch_at;
  };
  std::optional<stun::Endpoint> relay_ep;
  std::uint16_t relay_tls_port = 0;
  relay::TokenBytes relay_token{};
  // Waits for a PunchIn newer than `seen`.
  auto wait_plan = [&](std::uint64_t seen) -> std::optional<Plan> {
    std::unique_lock lock(sig.mu);
    const bool got = sig.cv.wait_for(lock, signal_timeout, [&] {
      return sig.closed || (sig.punch_seq > seen && !sig.key.empty());
    });
    if (!got || sig.punch_seq <= seen || sig.key.empty() || sig.peer_candidates.empty())
      return std::nullopt;
    relay_ep = sig.relay;
    relay_tls_port = sig.relay_tls_port;
    relay_token = sig.relay_token;
    return Plan{sig.peer_candidates, sig.peer_nat, sig.key, sig.punch_received + *sig.punch_delay};
  };
  auto punch_seq = [&] {
    std::lock_guard lock(sig.mu);
    return sig.punch_seq;
  };

  // The order matters for port prediction: a sequential NAT often counts ports for the whole
  // host, so every new destination of ANY socket here uses up the next public port. Measure the
  // relays first, then the NAT (gather), then send the candidates, so that nothing new is sent
  // between the NAT measurement and the punch.
  std::vector<stun::Endpoint> relays;
  {
    std::unique_lock lock(sig.mu);
    sig.cv.wait_for(lock, signal_timeout, [&] { return sig.closed || sig.relays_received; });
    relays = sig.relays;
  }
  if (!relays.empty()) {
    pb::AgentMsg rtts;
    for (const auto& [i, us] : agent::measure_relays(sock, relays, std::chrono::milliseconds(300))) {
      auto* r = rtts.mutable_relay_rtts()->add_rtts();
      r->set_index(i);
      r->set_rtt_us(us);
    }
    write(rtts);  // before the candidates: they trigger the pairing, which picks the relay
  }
  gather();
  write(candidates_msg());

  auto plan = wait_plan(0);
  if (!plan) {
    std::fputs("pierce-agent: no PunchIn from the coordination server\n", stderr);
    stop_signaling();
    return fail(0);
  }

  // One direct attempt. Kept in a heap object because the Puncher refers to its sockets.
  struct DirectAttempt {
    std::vector<stun::UdpSocket> birthday_socks;
    std::optional<agent::Puncher> puncher;
    agent::PunchResult res;
  };
  auto try_direct = [&](const Plan& p) {
    auto at = std::make_unique<DirectAttempt>();
    auto peer_cands = p.peer_cands;
    // Stage 3 techniques, chosen from both sides' NAT mapping. They need the peer's public IP (its
    // srflx candidate); predictions and guesses never go to any other address.
    using agent::Mapping;
    auto peer_srflx = std::find_if(peer_cands.begin(), peer_cands.end(), [](const Candidate& c) {
      return c.type == CandidateType::ServerReflexive;
    });
    std::optional<stun::Endpoint> birthday_target;
    if (peer_srflx != peer_cands.end()) {
      const auto peer_ip = peer_srflx->ep.ipv4;
      const auto peer_srflx_ep = peer_srflx->ep;  // the insertions below invalidate peer_srflx
      // Peer behind a sequential NAT: probe the ports it will use next.
      const bool we_seq = my_nat.mapping == Mapping::SymmetricSequential;
      auto predicted =
          agent::predicted_candidates(peer_ip, p.peer_nat, we_seq, mine.size(), predict_window);
      peer_cands.insert(peer_cands.end(), predicted.begin(), predicted.end());
      // Random mapping on one side, cone on the other: birthday probing.
      if (my_nat.mapping == Mapping::EndpointIndependent &&
          p.peer_nat.mapping == Mapping::SymmetricRandom) {
        auto guesses = agent::guessed_candidates(peer_ip, birthday);
        peer_cands.insert(peer_cands.end(), guesses.begin(), guesses.end());
      } else if (my_nat.mapping == Mapping::SymmetricRandom &&
                 p.peer_nat.mapping == Mapping::EndpointIndependent && birthday > 0) {
        for (int i = 0; i < birthday; ++i) at->birthday_socks.emplace_back();
        birthday_target = peer_srflx_ep;
      }
    }
    // Wait for the agreed moment, then probe.
    std::this_thread::sleep_until(p.punch_at);
    at->puncher.emplace(sock, p.key, peer_cands);
    if (birthday_target) at->puncher->add_birthday_sockets(at->birthday_socks, *birthday_target);
    at->res = at->puncher->connect(popt);
    return at;
  };

  // 3. Punch.
  auto direct = try_direct(*plan);
  auto& puncher = *direct->puncher;
  auto res = direct->res;
  agent::Puncher* active = &puncher;
  const char* path_name = "direct";
  int probes = puncher.probes_sent();

  // 4. Direct failed: fall back to the relay. Both peers reach this point at about the same
  //    time (same punch moment, same timeout), bind with the shared token, and probe each other
  //    through it. The relay is just another candidate whose packets the relay forwards.
  std::optional<agent::Puncher> via_relay;
  std::optional<agent::TlsRelayShim> tls_shim;
  if (!res.success && relay_ep) {
    // UDP to the relay first. If that gets no answer (a network that blocks UDP), the same relay
    // over TCP/TLS, through a shim that makes it look like a UDP relay at a loopback address.
    std::optional<stun::Endpoint> relay_at;
    if (agent::bind_relay(sock, *relay_ep, relay_token, std::chrono::milliseconds(200), 5)) {
      relay_at = relay_ep;
    } else if (relay_tls_port != 0) {
      try {
        tls_shim.emplace(stun::Endpoint{relay_ep->ipv4, relay_tls_port}, std::chrono::milliseconds(2000));
        if (agent::bind_relay(sock, tls_shim->local(), relay_token, std::chrono::milliseconds(300), 5))
          relay_at = tls_shim->local();
      } catch (const std::exception& e) {
        std::fprintf(stderr, "pierce-agent: TLS relay: %s\n", e.what());
      }
    }
    if (relay_at) {
      via_relay.emplace(sock, plan->key,
                        std::vector<Candidate>{{CandidateType::Relayed, *relay_at,
                                                agent::priority(CandidateType::Relayed)}});
      agent::PunchOptions ropt = popt;
      // Long enough to overlap with a peer that reaches the relay a bit later (e.g. it first
      // waited for the UDP relay to answer, then went over TLS).
      ropt.timeout = std::chrono::milliseconds(3000);
      res = via_relay->connect(ropt);
      probes += via_relay->probes_sent();
      active = &*via_relay;
      path_name = tls_shim ? "relay-tls" : "relay";
    }
  }
  if (!res.success) {
    stop_signaling();
    return fail(probes);
  }
  const auto ttc =
      std::chrono::duration_cast<std::chrono::milliseconds>(res.connected_at - signaling_start);
  std::printf("%d,%lld,%d,%s,%s\n", via_relay ? 0 : 1, static_cast<long long>(ttc.count()), probes,
              path_name, stun::to_string(*res.path).c_str());
  std::fflush(stdout);

#ifdef PIERCE_HAVE_WIREGUARD
  // 5a. Stage 4: carry real traffic. WireGuard runs over the socket and path that just worked
  //     (a birthday socket, the main socket, or the main socket via the relay).
  if (tun) {
    wg::DataPlane dp(*tun, *tunnel, active->socket(res.local), *res.path, plan->key);
    std::fputs("dataplane up\n", stderr);
    const auto until = hold_s > 0 ? Clock::now() + std::chrono::seconds(hold_s)
                                  : Clock::time_point::max();
    const auto st = dp.run(until);
    std::fprintf(stderr, "dataplane to_peer=%llu from_peer=%llu dropped=%llu\n",
                 static_cast<unsigned long long>(st.to_peer),
                 static_cast<unsigned long long>(st.from_peer),
                 static_cast<unsigned long long>(st.dropped));
    stop_signaling();
    return 0;
  }
#endif

  // 5. Optionally stay connected. Keepalives are peer to peer (or through the relay, which checks
  //    tokens on its own): the coordination server may die.
  if (hold_s > 0) {
    std::fputs("connected\n", stderr);
    agent::HoldStats total;
    const auto hold_end = Clock::now() + std::chrono::seconds(hold_s);
    const auto relayed_since = res.connected_at;
    auto next_retry = relayed_since + retry_direct;
    bool relayed = via_relay.has_value();
    for (auto now = Clock::now(); now < hold_end; now = Clock::now()) {
      const bool retry_due = relayed && retry_direct.count() > 0;
      const auto chunk_end = retry_due ? std::min(hold_end, next_retry) : hold_end;
      if (chunk_end > now) {
        const auto st = active->hold(res.local, *res.path,
                                     std::chrono::ceil<std::chrono::milliseconds>(chunk_end - now),
                                     keepalive);
        total.sent += st.sent;
        total.answered += st.answered;
      }
      if (!retry_due || Clock::now() < next_retry || Clock::now() >= hold_end) continue;
      next_retry += retry_direct;
      // The give-up rule's second half: while relayed, try the direct path again. This needs the
      // coordination server for a fresh punch moment; if it is gone we just stay on the relay.
      const auto seen = punch_seq();
      gather();
      write(candidates_msg());
      pb::AgentMsg retry;
      retry.mutable_retry_direct();
      write(retry);
      auto p2 = wait_plan(seen);
      if (!p2) continue;
      auto again = try_direct(*p2);
      if (!again->res.success) continue;
      // Upgraded: from now on keepalives go directly.
      const auto up = std::chrono::duration_cast<std::chrono::milliseconds>(
          again->res.connected_at - relayed_since);
      std::fprintf(stderr, "upgrade_ms=%lld\n", static_cast<long long>(up.count()));
      direct = std::move(again);
      active = &*direct->puncher;
      res = direct->res;
      relayed = false;
    }
    std::fprintf(stderr, "keepalive sent=%d answered=%d\n", total.sent, total.answered);
  }
  stop_signaling();
  return 0;
} catch (const std::exception& e) {
  std::fprintf(stderr, "pierce-agent: %s\n", e.what());
  std::printf("0,,0,none,\n");
  return 1;
}
