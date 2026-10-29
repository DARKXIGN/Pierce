#include <gtest/gtest.h>

#include <vector>

#include "wg/tunnel.hpp"

// The isolated BoringTun check from the roadmap: two tunnels in one process, no sockets, no TUN.
// Packets are handed from one to the other directly.

namespace {
// A minimal IPv4 packet (header + 4 bytes payload); BoringTun only looks at the version and
// length, the checksum is not checked.
std::vector<std::uint8_t> ip_packet(std::uint8_t marker) {
  return {0x45, 0, 0, 24, 0, 0, 0, 0, 64, 17, 0, 0, 10, 99, 0, 1, 10, 99, 0, 2,
          marker, marker, marker, marker};
}
std::vector<std::uint8_t> copy(std::span<const std::uint8_t> s) { return {s.begin(), s.end()}; }
}  // namespace

TEST(WgKeys, GenerateAndDerive) {
  const auto priv = wg::generate_private_key();
  EXPECT_EQ(priv.size(), 44u);
  EXPECT_TRUE(wg::valid_key(priv));
  const auto pub = wg::public_key(priv);
  ASSERT_TRUE(pub);
  EXPECT_NE(*pub, priv);
  EXPECT_EQ(wg::public_key(priv), pub);  // deterministic
  EXPECT_FALSE(wg::valid_key("not a key"));
  EXPECT_FALSE(wg::public_key("short"));
}

TEST(WgKeys, MatchesRfc7748Vector) {
  // RFC 7748 §6.1: Alice's private key 77076d0a...2c2a and public key 8520f009...4e6a, as base64.
  EXPECT_EQ(wg::public_key("dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo="),
            "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=");
}

TEST(WgTunnel, HandshakeThenDataBothWays) {
  const auto a_priv = wg::generate_private_key(), b_priv = wg::generate_private_key();
  wg::Tunnel a(a_priv, *wg::public_key(b_priv), 0, 1);
  wg::Tunnel b(b_priv, *wg::public_key(a_priv), 0, 2);

  // A wants to send a packet; with no session yet, BoringTun queues it and emits a handshake
  // initiation (type 1) instead.
  auto out = a.encapsulate(ip_packet(0xAA));
  ASSERT_EQ(out.op, wg::Tunnel::Op::ToNetwork);
  auto init = copy(out.data);
  EXPECT_EQ(init[0], 1);
  EXPECT_TRUE(wg::looks_like_wireguard(init));

  // B answers with a handshake response (type 2).
  out = b.decapsulate(init);
  ASSERT_EQ(out.op, wg::Tunnel::Op::ToNetwork);
  auto resp = copy(out.data);
  EXPECT_EQ(resp[0], 2);
  while (b.flush().op != wg::Tunnel::Op::Done) {}

  // A completes the handshake; flushing sends the queued packet as transport data (type 4).
  out = a.decapsulate(resp);
  std::vector<std::vector<std::uint8_t>> to_b;
  if (out.op == wg::Tunnel::Op::ToNetwork) to_b.push_back(copy(out.data));
  for (out = a.flush(); out.op == wg::Tunnel::Op::ToNetwork; out = a.flush())
    to_b.push_back(copy(out.data));
  ASSERT_FALSE(to_b.empty());

  bool got = false;
  for (const auto& d : to_b) {
    EXPECT_EQ(d[0], 4);
    auto r = b.decapsulate(d);
    if (r.op == wg::Tunnel::Op::ToTunnel) {
      EXPECT_EQ(copy(r.data), ip_packet(0xAA));
      got = true;
    }
  }
  EXPECT_TRUE(got);

  // And back from B to A, now without a handshake.
  out = b.encapsulate(ip_packet(0xBB));
  ASSERT_EQ(out.op, wg::Tunnel::Op::ToNetwork);
  auto back = copy(out.data);
  EXPECT_EQ(back[0], 4);
  // The plaintext marker must not appear in the encrypted datagram.
  EXPECT_EQ(std::search(back.begin(), back.end(), ip_packet(0xBB).end() - 4, ip_packet(0xBB).end()),
            back.end());
  auto r = a.decapsulate(back);
  ASSERT_EQ(r.op, wg::Tunnel::Op::ToTunnel);
  EXPECT_EQ(copy(r.data), ip_packet(0xBB));
}

TEST(WgTunnel, WrongPeerKeyFailsHandshake) {
  const auto a_priv = wg::generate_private_key(), b_priv = wg::generate_private_key();
  const auto stranger = wg::generate_private_key();
  wg::Tunnel a(a_priv, *wg::public_key(b_priv), 0, 1);
  wg::Tunnel b(b_priv, *wg::public_key(stranger), 0, 2);  // B expects someone else
  auto init = copy(a.encapsulate(ip_packet(1)).data);
  EXPECT_NE(b.decapsulate(init).op, wg::Tunnel::Op::ToNetwork);
}

TEST(WgTunnel, InvalidKeyThrows) {
  EXPECT_THROW(wg::Tunnel("bad", wg::generate_private_key(), 0), std::invalid_argument);
}
