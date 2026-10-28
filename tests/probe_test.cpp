#include <gtest/gtest.h>

#include <string>

#include "agent/probe.hpp"

namespace {
const probe::Key kKey(32, 0x42);
}

TEST(Probe, RoundTrip) {
  probe::Probe p{probe::Kind::Response, probe::random_tid()};
  auto bytes = probe::encode(p, kKey);
  EXPECT_EQ(bytes.size(), 23u);
  EXPECT_EQ(bytes[0], 0xFF);
  EXPECT_TRUE(probe::looks_like_probe(bytes));
  auto back = probe::decode(bytes, kKey);
  ASSERT_TRUE(back);
  EXPECT_EQ(back->kind, probe::Kind::Response);
  EXPECT_EQ(back->tid, p.tid);
}

// RFC 4231 test case 2: HMAC-SHA256(key "Jefe", "what do ya want for nothing?") begins with
// 5bdcc146bf60754e. Checks we call OpenSSL's HMAC correctly, not just consistently.
TEST(Probe, MacMatchesRfc4231Vector) {
  const probe::Key jefe = {'J', 'e', 'f', 'e'};
  const std::string msg = "what do ya want for nothing?";
  const auto m = probe::mac8(
      std::span(reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size()), jefe);
  const std::array<std::uint8_t, 8> expected = {0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e};
  EXPECT_EQ(m, expected);
}

TEST(Probe, AnyFlippedByteBreaksVerification) {
  const auto bytes = probe::encode({probe::Kind::Request, probe::random_tid()}, kKey);
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    auto copy = bytes;
    copy[i] ^= 0x01;
    EXPECT_FALSE(probe::decode(copy, kKey)) << "byte " << i;
  }
}

TEST(Probe, RejectsWrongKeyAndTamperedMac) {
  auto bytes = probe::encode({probe::Kind::Request, probe::random_tid()}, kKey);
  EXPECT_FALSE(probe::decode(bytes, probe::Key(32, 0x43)));
  bytes[22] ^= 0x80;
  EXPECT_FALSE(probe::decode(bytes, kKey));
}

TEST(Probe, RejectsWrongSizeAndNonProbes) {
  auto bytes = probe::encode({probe::Kind::Request, probe::random_tid()}, kKey);
  EXPECT_FALSE(probe::decode(std::span(bytes).first(22), kKey));
  std::vector<std::uint8_t> stun(20, 0);  // STUN starts with 0x00
  EXPECT_FALSE(probe::looks_like_probe(stun));
  EXPECT_FALSE(probe::decode(stun, kKey));
}

TEST(Probe, TransactionIdsDiffer) {
  EXPECT_NE(probe::random_tid(), probe::random_tid());
}
