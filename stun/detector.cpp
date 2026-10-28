#include "stun/detector.hpp"

#include <cstdlib>

#include "stun/client.hpp"

namespace stun {

std::string_view to_string(NatType t) {
  switch (t) {
    case NatType::Full: return "full";
    case NatType::Restricted: return "restricted";
    case NatType::PortRestricted: return "port-restricted";
    case NatType::SymmetricRandom: return "symmetric-random";
    case NatType::SymmetricSequential: return "symmetric-sequential";
    case NatType::Unknown: break;
  }
  return "no-response";
}

NatType classify(const Observations& o) {
  if (!o.mapped_primary || !o.mapped_alt_ip || !o.mapped_alt_port) return NatType::Unknown;
  const int p1 = o.mapped_primary->port, p2 = o.mapped_alt_ip->port, p3 = o.mapped_alt_port->port;
  if (p1 != p2 || p2 != p3) {
    // A random allocator practically never produces two equal small steps in a row.
    const int step1 = p2 - p1, step2 = p3 - p2;
    constexpr int kMaxStep = 16;
    if (step1 == step2 && step1 != 0 && std::abs(step1) <= kMaxStep)
      return NatType::SymmetricSequential;
    return NatType::SymmetricRandom;
  }
  if (o.reached_from_other_ip) return NatType::Full;
  if (o.reached_from_other_port) return NatType::Restricted;
  return NatType::PortRestricted;
}

UdpSocket& Detector::fresh_socket() {
  sockets_.emplace_back();  // port 0: the kernel picks a free local port
  return sockets_.back();
}

std::optional<Message> Detector::transact(UdpSocket& sock, const Endpoint& to,
                                          std::uint8_t change) {
  return binding(sock, to, change, cfg_.timeout, cfg_.tries);
}

Observations Detector::observe() {
  Observations o;
  const Endpoint primary = cfg_.server;
  const Endpoint alt_ip{cfg_.alt_ip, primary.port};
  const Endpoint alt_port{primary.ipv4, cfg_.alt_port};

  // 1. Mapping: one socket, three destinations.
  auto& s = fresh_socket();
  auto mapped = [&](const Endpoint& to) -> std::optional<Endpoint> {
    if (auto m = transact(s, to, 0)) return m->xor_mapped;
    return std::nullopt;
  };
  o.mapped_primary = mapped(primary);
  o.mapped_alt_ip = mapped(alt_ip);
  o.mapped_alt_port = mapped(alt_port);
  if (!o.mapped_primary || !o.mapped_alt_ip || !o.mapped_alt_port) return o;
  // Symmetric NATs filter by remote ip:port anyway; no need to spend time on filtering tests.
  if (classify(o) != NatType::PortRestricted) return o;

  // 2. Filtering, each test on its own fresh socket that has only talked to the primary address,
  // so one test cannot open the NAT's filter for the other.
  auto filter_test = [&](std::uint8_t change) {
    auto& f = fresh_socket();
    if (!transact(f, primary, 0)) return false;  // open a mapping to the primary address first
    return transact(f, primary, change).has_value();
  };
  o.reached_from_other_ip = filter_test(kChangeIp);
  if (!o.reached_from_other_ip) o.reached_from_other_port = filter_test(kChangePort);
  return o;
}

}  // namespace stun
