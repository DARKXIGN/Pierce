#include "agent/predict.hpp"

#include <algorithm>
#include <cstdlib>

namespace agent {

NatInfo characterize(std::uint16_t p1, std::uint16_t p2, std::uint16_t p3) {
  NatInfo n;
  n.last_port = p3;
  if (p1 == p2 && p2 == p3) {
    n.mapping = Mapping::EndpointIndependent;
    return n;
  }
  const int step1 = int{p2} - p1, step2 = int{p3} - p2;
  constexpr int kMaxStep = 16;
  if (step1 == step2 && step1 != 0 && std::abs(step1) <= kMaxStep) {
    n.mapping = Mapping::SymmetricSequential;
    n.step = step1;
  } else {
    n.mapping = Mapping::SymmetricRandom;
  }
  return n;
}

std::vector<Candidate> predicted_candidates(const std::array<std::uint8_t, 4>& peer_ip,
                                            const NatInfo& peer, bool we_are_sequential,
                                            std::size_t our_candidate_count, int window) {
  std::vector<Candidate> out;
  if (peer.mapping != Mapping::SymmetricSequential || peer.step == 0) return out;
  window = std::clamp(window, 0, 256);  // the probing cap from the design
  const int offset = we_are_sequential ? static_cast<int>(our_candidate_count) : 0;
  for (int k = 1; k <= window; ++k) {
    const long port = long{peer.last_port} + long{offset + k} * peer.step;
    if (port < 1 || port > 65535) continue;
    // Decreasing local preference keeps the predictions in order k = 1, 2, ... after sorting.
    const auto pri = priority(CandidateType::Predicted, static_cast<std::uint16_t>(65535 - k));
    out.push_back({CandidateType::Predicted, {peer_ip, static_cast<std::uint16_t>(port)}, pri});
  }
  return out;
}

}  // namespace agent
