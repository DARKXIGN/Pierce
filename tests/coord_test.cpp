#include <gtest/gtest.h>

#include "coord/db.hpp"
#include "coord/service.hpp"
#include "coord/timing.hpp"

using namespace std::chrono_literals;

TEST(PunchDelays, EqualRttsGiveEqualDelays) {
  const auto d = coord::punch_delays(40ms, 40ms, 20ms);
  EXPECT_EQ(d.a, 20ms);  // X = 20 + 20 = 40, delay = 40 - 20
  EXPECT_EQ(d.b, 20ms);
}

TEST(PunchDelays, FartherPeerWaitsLess) {
  // A is 10 ms away (RTT), B 200 ms. X = 100 + 20 = 120.
  const auto d = coord::punch_delays(10ms, 200ms, 20ms);
  EXPECT_EQ(d.a, 115ms);
  EXPECT_EQ(d.b, 20ms);
  // Both start at the same moment after the server sends: one-way delay + own delay = X.
  EXPECT_EQ(10ms / 2 + d.a, 200ms / 2 + d.b);
}

TEST(NodeDb, UpsertAndUpdate) {
  coord::NodeDb db(":memory:");
  db.upsert_node("A", "B");
  db.upsert_node("A", "C");  // same node again: update, not a second row
  db.upsert_node("x'; DROP TABLE nodes; --", "A");
  db.set_candidates("A", "srflx 203.0.113.1:4000");
  db.set_rtt("A", 1.5);
  EXPECT_EQ(db.count_nodes(), 2);
}

TEST(PickRelay, LowestSumReachedByBoth) {
  // Relay 0: 10 + 90 = 100. Relay 1: 40 + 40 = 80. Relay 2: only A reached it.
  std::map<std::uint32_t, std::uint32_t> a = {{0, 10}, {1, 40}, {2, 1}}, b = {{0, 90}, {1, 40}};
  EXPECT_EQ(coord::pick_relay(3, a, b), 1u);
  EXPECT_EQ(coord::pick_relay(3, {}, {}), 0u);  // nothing measured: the default
}
