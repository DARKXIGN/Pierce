#pragma once
#include <cstdint>
#include <optional>
#include <vector>

#include "agent/candidates.hpp"

// Port prediction for symmetric NATs that allocate ports in sequence.
namespace agent {

enum class Mapping { Unknown, EndpointIndependent, SymmetricRandom, SymmetricSequential };

struct NatInfo {
  Mapping mapping = Mapping::Unknown;
  std::uint16_t last_port = 0;  // public port seen by the last STUN request
  int step = 0;                 // port increase per new destination (sequential only)
};

// From the public ports one socket got for three different destinations, in the order sent.
// Same rule as the detector: three equal ports are endpoint-independent; two equal steps of at
// most 16 are sequential; anything else is random.
NatInfo characterize(std::uint16_t p1, std::uint16_t p2, std::uint16_t p3);

// Candidates to probe when the peer's NAT is sequential.
//
// A sequential NAT gives every NEW destination of the peer's socket the next port: the peer's
// i-th distinct destination gets last_port + i * step. During punching the peer first sends one
// probe to each of our real candidates (i = 1..n, n = how many candidates we sent it), in
// priority order, then to its own predictions, if it predicts too.
//
//   - We are not sequential: the mapping the peer uses toward us is among i = 1..n, so we probe
//     last_port + k * step for k = 1..window.
//   - We are sequential too: we both probe predictions in the same order, k = 1, 2, ... The
//     peer's k-th prediction leaves from its mapping n + k, and to get through our NAT our k-th
//     prediction must target exactly that one, so we probe last_port + (n + k) * step. The same
//     reasoning from the other side makes its k-th prediction hit our mapping for our k-th
//     prediction, so the two probes pass each other's filters.
//
// `peer_ip` is the peer's public IP (from its server-reflexive candidate); predictions never go
// anywhere else. Ports outside 1..65535 are skipped. `window` is capped at 256.
std::vector<Candidate> predicted_candidates(const std::array<std::uint8_t, 4>& peer_ip,
                                            const NatInfo& peer, bool we_are_sequential,
                                            std::size_t our_candidate_count, int window);

}  // namespace agent
