#include <gtest/gtest.h>

#include "relay/protocol.hpp"
#include "relay/table.hpp"

using relay::Endpoint;

namespace {
const relay::Secret kSecret(32, 0x5A);
constexpr std::uint64_t kNow = 1'800'000'000;
relay::TokenBytes token(std::uint8_t id, std::uint64_t expires = kNow + 600) {
  relay::Token t;
  t.session.fill(id);
  t.expires = expires;
  return relay::issue_token(t, kSecret);
}
const Endpoint kA{{198, 51, 100, 1}, 4000}, kB{{198, 51, 100, 2}, 5000};
const std::vector<std::uint8_t> kData = {0x04, 1, 2, 3};  // e.g. a WireGuard data packet
}  // namespace

TEST(RelayToken, VerifiesAndRejects) {
  const auto t = token(7);
  auto ok = relay::verify_token(t, kSecret, kNow);
  ASSERT_TRUE(ok);
  EXPECT_EQ(ok->session[0], 7);
  EXPECT_FALSE(relay::verify_token(t, relay::Secret(32, 0x5B), kNow));  // other secret
  EXPECT_FALSE(relay::verify_token(t, kSecret, kNow + 601));            // expired
  auto forged = t;
  forged[16] ^= 1;  // push the expiry out without knowing the secret
  EXPECT_FALSE(relay::verify_token(forged, kSecret, kNow));
}

TEST(RelayTable, ForwardsBetweenTheTwoBoundPeers) {
  relay::Table t(kSecret, std::chrono::seconds(60));
  EXPECT_FALSE(t.handle(kData, kA, kNow));  // not bound: dropped
  auto bound = t.handle(relay::bind_message(token(1)), kA, kNow);
  ASSERT_TRUE(bound);
  EXPECT_EQ(bound->bytes, relay::bound_message());
  EXPECT_FALSE(t.handle(kData, kA, kNow));  // B not there yet
  ASSERT_TRUE(t.handle(relay::bind_message(token(1)), kB, kNow));
  auto fwd = t.handle(kData, kA, kNow);
  ASSERT_TRUE(fwd);
  EXPECT_EQ(fwd->to, kB);
  EXPECT_EQ(fwd->bytes, kData);
  EXPECT_EQ(t.handle(kData, kB, kNow)->to, kA);
}

TEST(RelayTable, SessionsAreIsolatedAndBadTokensIgnored) {
  relay::Table t(kSecret, std::chrono::seconds(60));
  t.handle(relay::bind_message(token(1)), kA, kNow);
  t.handle(relay::bind_message(token(2)), kB, kNow);
  EXPECT_FALSE(t.handle(kData, kA, kNow));  // A and B are in different sessions
  auto bad = token(1);
  bad[30] ^= 1;
  EXPECT_FALSE(t.handle(relay::bind_message(bad), {{1, 1, 1, 1}, 1}, kNow));
  EXPECT_EQ(t.sessions(), 2u);
}

TEST(RelayTable, RebindReplacesQuietestSlot) {
  relay::Table t(kSecret, std::chrono::seconds(60));
  t.handle(relay::bind_message(token(1)), kA, kNow);
  t.handle(relay::bind_message(token(1)), kB, kNow + 5);
  const Endpoint a2{kA.ipv4, 4001};  // A's NAT gave it a new port
  t.handle(relay::bind_message(token(1)), a2, kNow + 10);
  EXPECT_EQ(t.handle(kData, kB, kNow + 10)->to, a2);
  EXPECT_FALSE(t.handle(kData, kA, kNow + 10));  // old endpoint no longer bound
}

TEST(RelayTable, PingPongAndExpiry) {
  relay::Table t(kSecret, std::chrono::seconds(60));
  auto pong = t.handle(relay::ping_message(42), kA, kNow);
  ASSERT_TRUE(pong);
  EXPECT_EQ(relay::control_type(pong->bytes), relay::Type::Pong);
  EXPECT_EQ(relay::nonce_of(pong->bytes), 42u);
  EXPECT_EQ(pong->bytes.size(), relay::ping_message(42).size());  // no amplification

  t.handle(relay::bind_message(token(1, kNow + 30)), kA, kNow);
  t.handle(relay::bind_message(token(1, kNow + 30)), kB, kNow);
  t.expire(kNow + 31);  // token expired
  EXPECT_EQ(t.sessions(), 0u);
  EXPECT_FALSE(t.handle(kData, kA, kNow + 31));
}

TEST(RelaySecret, FromHex) {
  EXPECT_EQ(relay::secret_from_hex("00ff5A"), (relay::Secret{0x00, 0xFF, 0x5A}));
  EXPECT_FALSE(relay::secret_from_hex("abc"));
  EXPECT_FALSE(relay::secret_from_hex("zz"));
  EXPECT_FALSE(relay::secret_from_hex(""));
}
