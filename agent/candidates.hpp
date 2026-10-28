#pragma once
#include <cstdint>
#include <string_view>
#include <vector>

#include "stun/message.hpp"

// ICE-style candidates (RFC 8445): addresses at which a peer might be reachable.
namespace agent {

using stun::Endpoint;

enum class CandidateType {
  Host,             // an address of a local interface, e.g. 10.0.1.2:41000
  ServerReflexive,  // our public address as a STUN server saw it
  PeerReflexive,    // learned during probing: where the peer's probe actually came from
  Predicted,        // a guessed port behind the peer's symmetric NAT (predict.hpp)
  Relayed,          // a relay that forwards to the peer (stage 3 fallback)
};

struct Candidate {
  CandidateType type = CandidateType::Host;
  Endpoint ep;
  std::uint32_t priority = 0;
  bool operator==(const Candidate&) const = default;
};

std::string_view to_string(CandidateType t);

// RFC 8445 §5.1.2.1 with one component: 2^24 * type preference + 2^8 * local preference + 255.
// Type preferences: host 126, peer-reflexive 110, server-reflexive 100, predicted 50 (not in
// RFC 8445; predictions go after every real candidate), relayed 0.
std::uint32_t priority(CandidateType t, std::uint16_t local_preference = 65535);

// Host candidates: every up, non-loopback IPv4 interface address, paired with `port` (the port of
// the one UDP socket everything is sent from).
std::vector<Candidate> host_candidates(std::uint16_t port);

// Highest priority first; duplicates (same ip:port) removed, keeping the higher-priority one.
void sort_and_dedupe(std::vector<Candidate>& cands);

}  // namespace agent
