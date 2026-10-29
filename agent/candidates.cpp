#include "agent/candidates.hpp"

#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>

#include <algorithm>
#include <cstring>

#include "stun/udp.hpp"

namespace agent {

std::string_view to_string(CandidateType t) {
  switch (t) {
    case CandidateType::Host: return "host";
    case CandidateType::ServerReflexive: return "srflx";
    case CandidateType::PortMapped: return "portmap";
    case CandidateType::PeerReflexive: return "prflx";
    case CandidateType::Predicted: return "predicted";
    case CandidateType::Relayed: return "relay";
  }
  return "?";
}

std::uint32_t priority(CandidateType t, std::uint16_t local_preference) {
  std::uint32_t type_pref = 0;
  switch (t) {
    case CandidateType::Host: type_pref = 126; break;
    case CandidateType::PeerReflexive: type_pref = 110; break;
    case CandidateType::ServerReflexive: type_pref = 100; break;
    case CandidateType::PortMapped: type_pref = 105; break;
    case CandidateType::Predicted: type_pref = 50; break;
    case CandidateType::Relayed: type_pref = 0; break;
  }
  return (type_pref << 24) | (std::uint32_t{local_preference} << 8) | 255;
}

std::vector<Candidate> host_candidates(std::uint16_t port, std::string_view exclude) {
  std::vector<Candidate> out;
  ifaddrs* list = nullptr;
  if (getifaddrs(&list) != 0) return out;
  // Local preference: IPv6 above IPv4 (as RFC 8421 suggests for dual-stack hosts), and within a
  // family later interfaces slightly lower, so priorities stay unique.
  std::uint16_t pref6 = 65535, pref4 = 32767;
  for (auto* ifa = list; ifa; ifa = ifa->ifa_next) {
    if (!ifa->ifa_addr) continue;
    const int family = ifa->ifa_addr->sa_family;
    if (family != AF_INET && family != AF_INET6) continue;
    if (!(ifa->ifa_flags & IFF_UP) || (ifa->ifa_flags & IFF_LOOPBACK)) continue;
    if (!exclude.empty() && exclude == ifa->ifa_name) continue;
    Endpoint ep = stun::from_sockaddr(ifa->ifa_addr);
    ep.port = port;
    if (family == AF_INET6) {
      // Link-local fe80::/10 needs an interface index to be usable and never reaches another
      // network; IPv4-mapped addresses are IPv4 candidates in disguise.
      if ((ep.ip[0] == 0xFE && (ep.ip[1] & 0xC0) == 0x80) || ep.is_v4()) continue;
      out.push_back({CandidateType::Host, ep, priority(CandidateType::Host, pref6--)});
    } else {
      out.push_back({CandidateType::Host, ep, priority(CandidateType::Host, pref4--)});
    }
  }
  freeifaddrs(list);
  return out;
}

void sort_and_dedupe(std::vector<Candidate>& cands) {
  std::stable_sort(cands.begin(), cands.end(),
                   [](const Candidate& a, const Candidate& b) { return a.priority > b.priority; });
  std::vector<Candidate> out;
  for (const auto& c : cands)
    if (std::none_of(out.begin(), out.end(), [&](const Candidate& o) { return o.ep == c.ep; }))
      out.push_back(c);
  cands = std::move(out);
}

}  // namespace agent
