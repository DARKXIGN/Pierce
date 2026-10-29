#include <gtest/gtest.h>

#include <set>

#include "agent/predict.hpp"

using agent::Mapping;

TEST(Characterize, ThreeCases) {
  EXPECT_EQ(agent::characterize(4000, 4000, 4000).mapping, Mapping::EndpointIndependent);
  auto seq = agent::characterize(20000, 20001, 20002);
  EXPECT_EQ(seq.mapping, Mapping::SymmetricSequential);
  EXPECT_EQ(seq.step, 1);
  EXPECT_EQ(seq.last_port, 20002);
  EXPECT_EQ(agent::characterize(20010, 20006, 20002).step, -4);
  EXPECT_EQ(agent::characterize(41234, 1789, 59001).mapping, Mapping::SymmetricRandom);
}

TEST(Predict, NothingForNonSequentialPeers) {
  agent::NatInfo cone{Mapping::EndpointIndependent, 4000, 0};
  EXPECT_TRUE(agent::predicted_candidates({1, 2, 3, 4}, cone, false, 2, 32).empty());
}

TEST(Predict, ConeSideProbesTheNextPorts) {
  agent::NatInfo seq{Mapping::SymmetricSequential, 20002, 1};
  auto c = agent::predicted_candidates({203, 0, 113, 1}, seq, false, 2, 4);
  ASSERT_EQ(c.size(), 4u);
  EXPECT_EQ(c[0].ep.port, 20003);
  EXPECT_EQ(c[3].ep.port, 20006);
  EXPECT_EQ(c[0].ep.v4(), (std::array<std::uint8_t, 4>{203, 0, 113, 1}));
  EXPECT_GT(c[0].priority, c[1].priority);  // k = 1 first
  EXPECT_LT(c[0].priority, agent::priority(agent::CandidateType::ServerReflexive));
}

// Simulate two sequential NATs with the send order the puncher uses, and check that each side's
// k-th prediction passes the other side's filter.
TEST(Predict, BothSequentialPredictionsMeet) {
  const int n_a = 2, n_b = 2;               // candidates each side sent the other
  const std::uint16_t la = 20002, lb = 30010;  // last STUN ports
  const int sa = 1, sb = 2;
  agent::NatInfo a{Mapping::SymmetricSequential, la, sa}, b{Mapping::SymmetricSequential, lb, sb};
  // Each side first sends to the other's real candidates, then to its predictions.
  auto a_targets = agent::predicted_candidates({0, 0, 0, 2}, b, true, n_a, 8);
  auto b_targets = agent::predicted_candidates({0, 0, 0, 1}, a, true, n_b, 8);
  for (int k = 1; k <= 8; ++k) {
    // A's k-th prediction is its (n_b + k)-th destination, so it leaves from la + (n_b + k) * sa;
    // B's k-th prediction leaves from lb + (n_a + k) * sb. Each must target the other's source.
    const int a_src = la + (n_b + k) * sa;
    const int b_src = lb + (n_a + k) * sb;
    EXPECT_EQ(a_targets[k - 1].ep.port, b_src) << k;
    EXPECT_EQ(b_targets[k - 1].ep.port, a_src) << k;
  }
}

TEST(Predict, WindowCappedAndPortsInRange) {
  agent::NatInfo seq{Mapping::SymmetricSequential, 65530, 1};
  auto c = agent::predicted_candidates({1, 1, 1, 1}, seq, false, 2, 1000);
  EXPECT_EQ(c.size(), 5u);  // 65531..65535, the rest would overflow
  agent::NatInfo low{Mapping::SymmetricSequential, 100, 1};
  EXPECT_EQ(agent::predicted_candidates({1, 1, 1, 1}, low, false, 2, 1000).size(), 256u);
}

TEST(Guess, DistinctPortsOnPeerIpCapped) {
  auto c = agent::guessed_candidates({198, 51, 100, 9}, 1000);
  ASSERT_EQ(c.size(), 256u);
  std::set<std::uint16_t> ports;
  for (const auto& g : c) {
    EXPECT_EQ(g.ep.v4(), (std::array<std::uint8_t, 4>{198, 51, 100, 9}));
    EXPECT_GE(g.ep.port, 1024);
    ports.insert(g.ep.port);
  }
  EXPECT_EQ(ports.size(), 256u);
  // Guesses rank below predictions.
  agent::NatInfo seq{Mapping::SymmetricSequential, 20000, 1};
  auto pred = agent::predicted_candidates({1, 1, 1, 1}, seq, false, 2, 256);
  for (const auto& g : c) EXPECT_LT(g.priority, pred.back().priority);
}
