#include <gtest/gtest.h>

#include <future>

#include "agent/candidates.hpp"
#include "agent/punch.hpp"

using agent::Candidate;
using agent::CandidateType;
using stun::Endpoint;

namespace {
const probe::Key kKey(32, 7);
Candidate host(const Endpoint& ep) {
  return {CandidateType::Host, ep, agent::priority(CandidateType::Host)};
}
}  // namespace

TEST(Candidates, PriorityOrdersHostThenPrflxThenSrflx) {
  EXPECT_GT(agent::priority(CandidateType::Host), agent::priority(CandidateType::PeerReflexive));
  EXPECT_GT(agent::priority(CandidateType::PeerReflexive),
            agent::priority(CandidateType::ServerReflexive));
  EXPECT_EQ(agent::priority(CandidateType::ServerReflexive), (100u << 24) | (65535u << 8) | 255u);
}

TEST(Candidates, SortAndDedupeKeepsHigherPriority) {
  const Endpoint a{{10, 0, 0, 1}, 1}, b{{10, 0, 0, 2}, 2};
  std::vector<Candidate> c = {
      {CandidateType::ServerReflexive, a, agent::priority(CandidateType::ServerReflexive)},
      host(b),
      host(a),
  };
  agent::sort_and_dedupe(c);
  ASSERT_EQ(c.size(), 2u);
  EXPECT_EQ(c[0].type, CandidateType::Host);
  EXPECT_EQ(c[1].type, CandidateType::Host);
}

// Two punchers on loopback, started at the same moment, must find each other.
TEST(Puncher, ConnectsOnLoopback) {
  stun::UdpSocket sa(Endpoint{{127, 0, 0, 1}, 0}), sb(Endpoint{{127, 0, 0, 1}, 0});
  agent::Puncher a(sa, kKey, {host(sb.local_endpoint())});
  agent::Puncher b(sb, kKey, {host(sa.local_endpoint())});
  agent::PunchOptions opt;
  opt.timeout = std::chrono::milliseconds(1000);
  auto fb = std::async(std::launch::async, [&] { return b.connect(opt); });
  const auto ra = a.connect(opt);
  const auto rb = fb.get();
  ASSERT_TRUE(ra.success);
  ASSERT_TRUE(rb.success);
  EXPECT_EQ(ra.path, sb.local_endpoint());
  EXPECT_EQ(rb.path, sa.local_endpoint());
  EXPECT_LT(a.probes_sent(), 10);
}

// The peer advertised a port it does not actually use: we only learn the real one from its
// probes (peer-reflexive candidate), and must still connect.
TEST(Puncher, LearnsPeerReflexiveCandidate) {
  stun::UdpSocket sa(Endpoint{{127, 0, 0, 1}, 0}), sb(Endpoint{{127, 0, 0, 1}, 0});
  stun::UdpSocket unused(Endpoint{{127, 0, 0, 1}, 0});
  agent::Puncher a(sa, kKey, {host(unused.local_endpoint())});  // wrong port for B
  agent::Puncher b(sb, kKey, {host(sa.local_endpoint())});
  agent::PunchOptions opt;
  opt.timeout = std::chrono::milliseconds(1000);
  auto fb = std::async(std::launch::async, [&] { return b.connect(opt); });
  const auto ra = a.connect(opt);
  const auto rb = fb.get();
  ASSERT_TRUE(ra.success);
  ASSERT_TRUE(rb.success);
  EXPECT_EQ(ra.path, sb.local_endpoint());
  EXPECT_EQ(a.remote().front().type, CandidateType::PeerReflexive);
}

TEST(Puncher, WrongKeyNeverConnects) {
  stun::UdpSocket sa(Endpoint{{127, 0, 0, 1}, 0}), sb(Endpoint{{127, 0, 0, 1}, 0});
  agent::Puncher a(sa, kKey, {host(sb.local_endpoint())});
  agent::Puncher b(sb, probe::Key(32, 8), {host(sa.local_endpoint())});
  agent::PunchOptions opt;
  opt.timeout = std::chrono::milliseconds(300);
  auto fb = std::async(std::launch::async, [&] { return b.connect(opt); });
  EXPECT_FALSE(a.connect(opt).success);
  EXPECT_FALSE(fb.get().success);
}

TEST(Puncher, IgnoresProbesFromUnsignaledAddresses) {
  stun::UdpSocket sa(Endpoint{{127, 0, 0, 1}, 0}), sb(Endpoint{{127, 0, 0, 2}, 0});
  // A only knows a candidate on 127.0.0.3, so B's probes from 127.0.0.2 are not answered.
  agent::Puncher a(sa, kKey, {host(Endpoint{{127, 0, 0, 3}, 9})});
  agent::Puncher b(sb, kKey, {host(sa.local_endpoint())});
  agent::PunchOptions opt;
  opt.timeout = std::chrono::milliseconds(300);
  auto fa = std::async(std::launch::async, [&] { return a.connect(opt); });
  EXPECT_FALSE(b.connect(opt).success);
  fa.get();
}

TEST(Puncher, HoldKeepsAnswering) {
  stun::UdpSocket sa(Endpoint{{127, 0, 0, 1}, 0}), sb(Endpoint{{127, 0, 0, 1}, 0});
  agent::Puncher a(sa, kKey, {host(sb.local_endpoint())});
  agent::Puncher b(sb, kKey, {host(sa.local_endpoint())});
  const auto d = std::chrono::milliseconds(300), i = std::chrono::milliseconds(50);
  auto fb = std::async(std::launch::async, [&] { return b.hold(sa.local_endpoint(), d, i); });
  const auto ha = a.hold(sb.local_endpoint(), d, i);
  const auto hb = fb.get();
  EXPECT_GE(ha.sent, 5);
  EXPECT_GE(ha.answered, ha.sent - 1);  // the last request may still be in flight at the end
  EXPECT_GE(hb.answered, hb.sent - 1);
}
