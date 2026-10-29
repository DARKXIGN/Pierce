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

TEST(StunMessage, RoundTripChangeRequest) {
  stun::Message m;
  m.type = stun::kBindingRequest;
  m.tid = stun::random_tid();
  m.change_request = stun::kChangeIp | stun::kChangePort;
  auto bytes = stun::encode(m);
  EXPECT_EQ(bytes.size(), 28u);  // header + one 8-byte attribute
  // Flags on the wire, RFC 5780 §7.2: value 0x00000006.
  EXPECT_EQ(bytes[27], 0x06);
  auto back = stun::decode(bytes);
  ASSERT_TRUE(back);
  EXPECT_EQ(back->change_request, stun::kChangeIp | stun::kChangePort);
}

// RFC 5769 §2.3: sample IPv6 Binding response, XOR-MAPPED-ADDRESS
// [2001:db8:1234:5678:11:2233:4455:6677]:32853.
TEST(StunMessage, DecodesRfc5769SampleIpv6Response) {
  const std::vector<std::uint8_t> bytes = {
      0x01, 0x01, 0x00, 0x48, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34,
      0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74,
      0x20, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x20, 0x00, 0x20, 0x00, 0x14, 0x00, 0x02,
      0xa1, 0x47, 0x01, 0x13, 0xa9, 0xfa, 0xa5, 0xd3, 0xf1, 0x79, 0xbc, 0x25, 0xf4, 0xb5,
      0xbe, 0xd2, 0xb9, 0xd9, 0x00, 0x08, 0x00, 0x14, 0xa3, 0x82, 0x95, 0x4e, 0x4b, 0xe6,
      0x7b, 0xf1, 0x17, 0x84, 0xc9, 0x7c, 0x82, 0x92, 0xc2, 0x75, 0xbf, 0xe3, 0xed, 0x41,
      0x80, 0x28, 0x00, 0x04, 0xc8, 0xfb, 0x0b, 0x4c};
  auto m = stun::decode(bytes);
  ASSERT_TRUE(m);
  ASSERT_TRUE(m->xor_mapped);
  const stun::Ipv6 want = {0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78,
                           0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
  EXPECT_EQ(*m->xor_mapped, stun::Endpoint::v6(want, 32853));
  EXPECT_FALSE(m->xor_mapped->is_v4());
}

TEST(StunMessage, RoundTripIpv6) {
  stun::Message m;
  m.type = stun::kBindingResponse;
  m.tid = stun::random_tid();
  m.xor_mapped = stun::Endpoint::v6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}, 41000);
  auto back = stun::decode(stun::encode(m));
  ASSERT_TRUE(back);
  EXPECT_EQ(back->xor_mapped, m.xor_mapped);
}

TEST(Endpoint, Ipv4IsMapped) {
  const stun::Endpoint e{{192, 0, 2, 1}, 80};
  EXPECT_TRUE(e.is_v4());
  EXPECT_EQ(e.v4(), (stun::Ipv4{192, 0, 2, 1}));
  EXPECT_EQ(e.ip[10], 0xFF);
  EXPECT_FALSE(stun::Endpoint{}.is_v4());  // "::" is IPv6 (any address)
}

#include "stun/udp.hpp"

TEST(EndpointText, ParseAndFormatBothFamilies) {
  auto v4 = stun::parse_endpoint("192.0.32.10:3478");
  ASSERT_TRUE(v4);
  EXPECT_TRUE(v4->is_v4());
  EXPECT_EQ(stun::to_string(*v4), "192.0.32.10:3478");
  auto v6 = stun::parse_endpoint("[2001:db8::2]:41000");
  ASSERT_TRUE(v6);
  EXPECT_FALSE(v6->is_v4());
  EXPECT_EQ(v6->port, 41000);
  EXPECT_EQ(stun::to_string(*v6), "[2001:db8::2]:41000");
  EXPECT_FALSE(stun::parse_endpoint("2001:db8::2:41000"));  // IPv6 needs brackets
  EXPECT_EQ(stun::address_bytes(*v4).size(), 4u);
  EXPECT_EQ(stun::address_bytes(*v6).size(), 16u);
  EXPECT_EQ(stun::from_address_bytes(stun::address_bytes(*v6), 41000), v6);
}
