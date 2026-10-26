#include <gtest/gtest.h>

#include "stun/message.hpp"

TEST(StunMessage, RoundTripBindingResponse) {
  stun::Message m;
  m.type = stun::kBindingResponse;
  m.tid = stun::random_tid();
  m.xor_mapped = stun::Endpoint{{192, 0, 2, 1}, 32853};

  auto bytes = stun::encode(m);
  auto back = stun::decode(bytes);
  ASSERT_TRUE(back.has_value());
  EXPECT_EQ(back->type, stun::kBindingResponse);
  EXPECT_EQ(back->tid, m.tid);
  ASSERT_TRUE(back->xor_mapped.has_value());
  EXPECT_EQ(*back->xor_mapped, *m.xor_mapped);
}

TEST(StunMessage, RequestHasNoAttributes) {
  stun::Message m;
  m.type = stun::kBindingRequest;
  m.tid = stun::random_tid();
  auto bytes = stun::encode(m);
  EXPECT_EQ(bytes.size(), 20u);
  auto back = stun::decode(bytes);
  ASSERT_TRUE(back);
  EXPECT_FALSE(back->xor_mapped);
}

// Sample IPv4 Binding response from RFC 5769 §2.2. It also carries SOFTWARE,
// MESSAGE-INTEGRITY and FINGERPRINT, which the decoder must skip.
TEST(StunMessage, DecodesRfc5769SampleResponse) {
  const std::vector<std::uint8_t> bytes = {
      0x01, 0x01, 0x00, 0x3c, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01,
      0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x0b,
      0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x20,
      0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43,
      0x00, 0x08, 0x00, 0x14, 0x2b, 0x91, 0xf5, 0x99, 0xfd, 0x9e, 0x90, 0xc3,
      0x8c, 0x74, 0x89, 0xf9, 0x2a, 0xf9, 0xba, 0x53, 0xf0, 0x6b, 0xe7, 0xd7,
      0x80, 0x28, 0x00, 0x04, 0xc0, 0x7d, 0x4c, 0x96};
  auto m = stun::decode(bytes);
  ASSERT_TRUE(m);
  EXPECT_EQ(m->type, stun::kBindingResponse);
  ASSERT_TRUE(m->xor_mapped);
  EXPECT_EQ(*m->xor_mapped, (stun::Endpoint{{192, 0, 2, 1}, 32853}));
}

TEST(StunMessage, RejectsBadMagicCookie) {
  stun::Message m;
  m.type = stun::kBindingRequest;
  auto bytes = stun::encode(m);
  bytes[4] ^= 0xFF;
  EXPECT_FALSE(stun::decode(bytes));
}

TEST(StunMessage, RejectsTruncated) {
  std::vector<std::uint8_t> bytes(10, 0);
  EXPECT_FALSE(stun::decode(bytes));
}

TEST(StunMessage, RejectsAttributeOverrunningMessage) {
  stun::Message m;
  m.type = stun::kBindingResponse;
  m.xor_mapped = stun::Endpoint{{10, 0, 0, 1}, 1234};
  auto bytes = stun::encode(m);
  bytes[23] = 0x40;  // attribute length 64 > message length 12
  EXPECT_FALSE(stun::decode(bytes));
}
