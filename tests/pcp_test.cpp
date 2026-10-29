#include <gtest/gtest.h>

#include "agent/pcp.hpp"
#include "agent/portmap.hpp"

TEST(Pcp, MapRequestLayout) {
  pcp::MapRequest r;
  r.client_ip = {10, 0, 1, 2};
  r.internal_port = 41000;
  r.suggested_external_port = 41000;
  r.lifetime_s = 7200;
  r.nonce.fill(0xAB);
  const auto b = pcp::encode(r);
  EXPECT_EQ(b.size(), 60u);
  EXPECT_EQ(b[0], 2);  // version 2
  EXPECT_EQ(b[1], 1);  // R=0, opcode MAP
  EXPECT_EQ((b[4] << 24) | (b[5] << 16) | (b[6] << 8) | b[7], 7200);
  // Client IP as ::ffff:10.0.1.2
  for (int i = 8; i < 18; ++i) EXPECT_EQ(b[i], 0) << i;
  EXPECT_EQ(b[18], 0xFF);
  EXPECT_EQ(b[19], 0xFF);
  EXPECT_EQ(b[20], 10);
  EXPECT_EQ(b[23], 2);
  EXPECT_EQ(b[24], 0xAB);  // nonce
  EXPECT_EQ(b[36], 17);    // UDP
  EXPECT_EQ((b[40] << 8) | b[41], 41000);
}

TEST(Pcp, DecodesMatchingResponseOnly) {
  pcp::Nonce nonce;
  nonce.fill(7);
  std::array<std::uint8_t, 60> resp{};
  resp[0] = 2;
  resp[1] = 0x81;  // response to MAP
  resp[3] = 0;     // SUCCESS
  resp[7] = 100;   // lifetime 100
  std::copy(nonce.begin(), nonce.end(), resp.begin() + 24);
  resp[36] = 17;
  resp[40] = 0xA0, resp[41] = 0x28;  // internal 41000
  resp[42] = 0xA0, resp[43] = 0x29;  // external 41001
  resp[54] = resp[55] = 0xFF;
  resp[56] = 192, resp[57] = 0, resp[58] = 32, resp[59] = 1;
  auto r = pcp::decode(resp, nonce);
  ASSERT_TRUE(r);
  EXPECT_EQ(r->result, 0);
  EXPECT_EQ(r->lifetime_s, 100u);
  EXPECT_EQ(r->external_port, 41001);
  EXPECT_EQ(r->external_ip, (pcp::Ipv4{192, 0, 32, 1}));

  auto other = nonce;
  other[0] = 8;
  EXPECT_FALSE(pcp::decode(resp, other));  // someone else's mapping
  resp[1] = 0x01;
  EXPECT_FALSE(pcp::decode(resp, nonce));  // a request, not a response
}

TEST(Portmap, ParseOption) {
  using P = agent::PortMapProtocol;
  EXPECT_EQ(agent::parse_portmap("auto"), (std::vector<P>{P::Pcp, P::NatPmp, P::Upnp}));
  EXPECT_EQ(agent::parse_portmap("off"), std::vector<P>{});
  EXPECT_EQ(agent::parse_portmap("upnp"), std::vector<P>{P::Upnp});
  EXPECT_FALSE(agent::parse_portmap("igd"));
}
