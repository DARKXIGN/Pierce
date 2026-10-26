#include <gtest/gtest.h>

#include <vector>

#include "lab/usernat/nat_table.hpp"
#include "lab/usernat/packet.hpp"

using namespace std::chrono_literals;
using usernat::Endpoint;

namespace {
constexpr Endpoint kInner{0x0A000102, 5000};   // 10.0.1.2:5000
constexpr Endpoint kStun1{0xCB00710A, 3478};   // 203.0.113.10:3478
constexpr Endpoint kStun2{0xCB00710B, 3478};   // 203.0.113.11:3478
const auto t0 = usernat::Clock::time_point{};
}  // namespace

TEST(UsernatTable, NewDestinationGetsNextPort) {
  usernat::Table t(20000, 20100, 1, 120s);
  EXPECT_EQ(t.outbound(kInner, kStun1, t0), 20000);
  EXPECT_EQ(t.outbound(kInner, kStun2, t0), 20001);
  EXPECT_EQ(t.outbound(kInner, kStun1, t0), 20000);  // existing flow keeps its port
  EXPECT_EQ(t.outbound({kInner.ip, 5001}, kStun1, t0), 20002);
}

TEST(UsernatTable, StepIsConfigurable) {
  usernat::Table t(20000, 20100, 4, 120s);
  EXPECT_EQ(t.outbound(kInner, kStun1, t0), 20000);
  EXPECT_EQ(t.outbound(kInner, kStun2, t0), 20004);
}

TEST(UsernatTable, InboundOnlyFromTheMappedRemote) {
  usernat::Table t(20000, 20100, 1, 120s);
  ASSERT_EQ(t.outbound(kInner, kStun1, t0), 20000);
  EXPECT_EQ(t.inbound(20000, kStun1, t0), kInner);
  EXPECT_FALSE(t.inbound(20000, kStun2, t0));                       // other IP
  EXPECT_FALSE(t.inbound(20000, {kStun1.ip, 3479}, t0));            // other port
  EXPECT_FALSE(t.inbound(20001, kStun1, t0));                       // no mapping
}

TEST(UsernatTable, IdleMappingsExpireAndTrafficRefreshes) {
  usernat::Table t(20000, 20100, 1, 30s);
  t.outbound(kInner, kStun1, t0);
  t.outbound(kInner, kStun2, t0);
  t.inbound(20000, kStun1, t0 + 20s);  // refreshes the first mapping only
  EXPECT_EQ(t.expire(t0 + 31s), 1u);
  EXPECT_TRUE(t.inbound(20000, kStun1, t0 + 31s));
  EXPECT_FALSE(t.inbound(20001, kStun2, t0 + 31s));
  // The sequence keeps going after an expiry rather than reusing the freed port.
  EXPECT_EQ(t.outbound(kInner, kStun2, t0 + 31s), 20002);
}

TEST(UsernatTable, WrapsAroundAndSkipsPortsInUse) {
  usernat::Table t(20000, 20002, 1, 120s);
  EXPECT_EQ(t.outbound(kInner, {kStun1.ip, 1}, t0), 20000);
  EXPECT_EQ(t.outbound(kInner, {kStun1.ip, 2}, t0), 20001);
  EXPECT_EQ(t.outbound(kInner, {kStun1.ip, 3}, t0), 20002);
  EXPECT_FALSE(t.outbound(kInner, {kStun1.ip, 4}, t0));  // full
  t.expire(t0 + 121s);
  EXPECT_EQ(t.outbound(kInner, {kStun1.ip, 5}, t0 + 121s), 20000);
}

namespace {
// 10.0.1.2:5000 -> 203.0.113.10:3478, payload "ping", checksums filled in by rewrite_dst.
std::vector<std::uint8_t> sample_packet() {
  std::vector<std::uint8_t> p = {
      0x45, 0x00, 0x00, 0x20, 0x12, 0x34, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00,  // IPv4, DF, TTL 64
      0x0A, 0x00, 0x01, 0x02, 0xCB, 0x00, 0x71, 0x0A,                          // src, dst
      0x13, 0x88, 0x0D, 0x96, 0x00, 0x0C, 0xFF, 0xFF,                          // UDP, cksum != 0
      'p',  'i',  'n',  'g'};
  usernat::rewrite_dst(p, kStun1);  // same dst; just computes valid checksums
  return p;
}

// Verifies a checksum the way a receiver does: summing over the data including the checksum
// field must give 0 (in one's complement, after inversion).
bool udp_checksum_ok(const std::vector<std::uint8_t>& p) {
  std::uint32_t pseudo = 0;
  for (int i = 12; i < 20; i += 2) pseudo += (p[i] << 8) | p[i + 1];
  pseudo += 17 + 12;
  return usernat::inet_checksum(std::span(p).subspan(20), pseudo) == 0;
}
}  // namespace

TEST(UsernatPacket, ParsesUdp) {
  auto p = sample_packet();
  auto info = usernat::parse_udp(p);
  ASSERT_TRUE(info);
  EXPECT_EQ(info->src, kInner);
  EXPECT_EQ(info->dst, kStun1);
}

TEST(UsernatPacket, RejectsFragmentsAndOtherProtocols) {
  auto p = sample_packet();
  p[6] = 0x20;  // MF flag
  EXPECT_FALSE(usernat::parse_udp(p));
  p = sample_packet();
  p[9] = 6;  // TCP
  EXPECT_FALSE(usernat::parse_udp(p));
  p = sample_packet();
  p.resize(25);  // shorter than the IP total length
  EXPECT_FALSE(usernat::parse_udp(p));
}

TEST(UsernatPacket, RewriteSourceKeepsChecksumsValid) {
  auto p = sample_packet();
  ASSERT_TRUE(usernat::rewrite_src(p, {0xCB007101, 20000}));  // 203.0.113.1:20000
  auto info = usernat::parse_udp(p);
  ASSERT_TRUE(info);
  EXPECT_EQ(info->src, (Endpoint{0xCB007101, 20000}));
  EXPECT_EQ(p[8], 62);  // TTL decremented twice (sample_packet + this rewrite)
  EXPECT_EQ(usernat::inet_checksum(std::span(p).first(20)), 0);
  EXPECT_TRUE(udp_checksum_ok(p));
}

TEST(UsernatPacket, ZeroUdpChecksumStaysZero) {
  auto p = sample_packet();
  p[26] = p[27] = 0;
  ASSERT_TRUE(usernat::rewrite_dst(p, kInner));
  EXPECT_EQ(p[26], 0);
  EXPECT_EQ(p[27], 0);
}

TEST(UsernatPacket, DropsWhenTtlRunsOut) {
  auto p = sample_packet();
  p[8] = 1;
  EXPECT_FALSE(usernat::rewrite_src(p, kInner));
}
