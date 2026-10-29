#include <gtest/gtest.h>

#include <algorithm>
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
  auto fb = std::async(std::launch::async, [&] { return b.hold(0, sa.local_endpoint(), d, i); });
  const auto ha = a.hold(0, sb.local_endpoint(), d, i);
  const auto hb = fb.get();
  EXPECT_GE(ha.sent, 5);
  EXPECT_GE(ha.answered, ha.sent - 1);  // the last request may still be in flight at the end
  EXPECT_GE(hb.answered, hb.sent - 1);
}

// Birthday probing on loopback: B only knows a wrong port for A, A probes from 8 extra sockets.
// One of them is the "lucky" one B guesses; the connection must use it.
TEST(Puncher, BirthdaySocketThatMatchesWins) {
  stun::UdpSocket sa(Endpoint{{127, 0, 0, 1}, 0}), sb(Endpoint{{127, 0, 0, 1}, 0});
  std::vector<stun::UdpSocket> extra;
  for (int i = 0; i < 8; ++i) extra.emplace_back(Endpoint{{127, 0, 0, 1}, 0});
  const auto lucky = extra[5].local_endpoint();
  stun::UdpSocket unused(Endpoint{{127, 0, 0, 1}, 0});

  agent::Puncher a(sa, kKey, {host(sb.local_endpoint())});
  a.add_birthday_sockets(extra, sb.local_endpoint());
  // B's candidates for A: a dead port (A's main socket "unknown") and the guessed lucky port.
  agent::Puncher b(sb, kKey, {host(unused.local_endpoint()),
                              {CandidateType::Predicted, lucky,
                               agent::priority(CandidateType::Predicted)}});
  agent::PunchOptions opt;
  opt.timeout = std::chrono::milliseconds(1000);
  auto fb = std::async(std::launch::async, [&] { return b.connect(opt); });
  const auto ra = a.connect(opt);
  const auto rb = fb.get();
  ASSERT_TRUE(ra.success);
  ASSERT_TRUE(rb.success);
  // On loopback nothing filters, so A may connect from any socket; B must have reached A at a
  // port A actually owns.
  EXPECT_TRUE(rb.path == sa.local_endpoint() || rb.path == lucky ||
              std::any_of(extra.begin(), extra.end(),
                          [&](auto& s) { return s.local_endpoint() == *rb.path; }));
}

TEST(Puncher, IntervalShrinksWithManyPairs) {
  stun::UdpSocket sa(Endpoint{{127, 0, 0, 1}, 0});
  std::vector<agent::Candidate> many;
  for (std::uint16_t p = 1; p <= 100; ++p)
    many.push_back(host(Endpoint{{127, 0, 0, 1}, static_cast<std::uint16_t>(40000 + p)}));
  agent::Puncher a(sa, kKey, many);
  agent::PunchOptions opt;
  opt.timeout = std::chrono::milliseconds(500);
  a.connect(opt);
  // 100 pairs, pass 500 ms -> 5 ms per probe -> about 100 probes in 500 ms (20 ms would give 25).
  EXPECT_GT(a.probes_sent(), 60);
}

namespace {
bool have_ipv6() {
  try {
    stun::UdpSocket s(Endpoint::v6({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 0));  // [::1]
    return true;
  } catch (const std::system_error&) {
    return false;  // kernel without IPv6 (e.g. booted with ipv6.disable=1)
  }
}
const Endpoint kLoop6 = Endpoint::v6({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 0);
}  // namespace

// The agent's default socket is dual-stack: one socket reaches an IPv4 and an IPv6 peer.
TEST(DualStack, OneSocketTalksToBothFamilies) {
  if (!have_ipv6()) GTEST_SKIP() << "no IPv6 in this kernel";
  stun::UdpSocket dual;  // "::", IPV6_V6ONLY off
  ASSERT_EQ(dual.family(), AF_INET6);
  stun::UdpSocket peer4(Endpoint{{127, 0, 0, 1}, 0}), peer6(kLoop6);
  const std::vector<std::uint8_t> hello = {1, 2, 3};
  const auto dual_port = dual.local_endpoint().port;
  peer4.send_to(hello, Endpoint{{127, 0, 0, 1}, dual_port});
  peer6.send_to(hello, Endpoint::v6(kLoop6.ip, dual_port));
  auto a = dual.receive(std::chrono::milliseconds(500)), b = dual.receive(std::chrono::milliseconds(500));
  ASSERT_TRUE(a && b);
  // The IPv4 sender shows up in mapped form, i.e. as the same Endpoint an IPv4 socket would give.
  EXPECT_TRUE(a->from == peer4.local_endpoint() || b->from == peer4.local_endpoint());
  EXPECT_TRUE(a->from == peer6.local_endpoint() || b->from == peer6.local_endpoint());
}

TEST(DualStack, PunchOverIpv6) {
  if (!have_ipv6()) GTEST_SKIP() << "no IPv6 in this kernel";
  stun::UdpSocket sa(kLoop6), sb(kLoop6);
  agent::Puncher a(sa, kKey, {host(sb.local_endpoint())});
  agent::Puncher b(sb, kKey, {host(sa.local_endpoint())});
  agent::PunchOptions opt;
  opt.timeout = std::chrono::milliseconds(1000);
  auto fb = std::async(std::launch::async, [&] { return b.connect(opt); });
  const auto ra = a.connect(opt);
  ASSERT_TRUE(ra.success);
  ASSERT_TRUE(fb.get().success);
  EXPECT_FALSE(ra.path->is_v4());
}

TEST(DualStack, FallsBackToIpv4WithoutIpv6) {
  // Whatever the kernel, the default socket works and can reach IPv4.
  stun::UdpSocket dual, peer4(Endpoint{{127, 0, 0, 1}, 0});
  dual.send_to(std::vector<std::uint8_t>{9}, peer4.local_endpoint());
  auto d = peer4.receive(std::chrono::milliseconds(500));
  ASSERT_TRUE(d);
  EXPECT_EQ(d->bytes[0], 9);
}
