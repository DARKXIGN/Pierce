#pragma once
#include <algorithm>
#include <chrono>

namespace coord {

struct PunchDelays {
  std::chrono::milliseconds a, b;
};

// Both PunchIn messages leave the server at the same time. Peer i receives its message about
// RTT_i / 2 later (one-way delay, assuming symmetric paths), then waits delay_i. Choosing
//   X = max(RTT_A, RTT_B) / 2 + margin,   delay_i = X - RTT_i / 2
// makes both peers start probing X after the send, i.e. at the same moment. The margin covers
// jitter and processing time.
inline PunchDelays punch_delays(std::chrono::milliseconds rtt_a, std::chrono::milliseconds rtt_b,
                                std::chrono::milliseconds margin) {
  const auto x = std::max(rtt_a, rtt_b) / 2 + margin;
  return {x - rtt_a / 2, x - rtt_b / 2};
}

}  // namespace coord
