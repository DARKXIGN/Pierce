#include "stun/message.hpp"

#include <algorithm>
#include <random>

namespace stun {
namespace {

// STUN is big-endian ("network byte order"), so we write the high byte first.
void put16(std::vector<std::uint8_t>& out, std::uint16_t v) {
  out.push_back(static_cast<std::uint8_t>(v >> 8));
  out.push_back(static_cast<std::uint8_t>(v & 0xFF));
}
void put32(std::vector<std::uint8_t>& out, std::uint32_t v) {
  put16(out, static_cast<std::uint16_t>(v >> 16));
  put16(out, static_cast<std::uint16_t>(v & 0xFFFF));
}
std::uint16_t get16(std::span<const std::uint8_t> b, std::size_t i) {
  return static_cast<std::uint16_t>((b[i] << 8) | b[i + 1]);
}
std::uint32_t get32(std::span<const std::uint8_t> b, std::size_t i) {
  return (static_cast<std::uint32_t>(get16(b, i)) << 16) | get16(b, i + 2);
}

// The bytes XOR-MAPPED-ADDRESS's address is XORed with: the magic cookie, then (for the rest of
// an IPv6 address) the transaction ID (RFC 8489 §14.2).
std::array<std::uint8_t, 16> xor_key(const TransactionId& tid) {
  std::array<std::uint8_t, 16> k{};
  k[0] = kMagicCookie >> 24;
  k[1] = (kMagicCookie >> 16) & 0xFF;
  k[2] = (kMagicCookie >> 8) & 0xFF;
  k[3] = kMagicCookie & 0xFF;
  std::copy(tid.begin(), tid.end(), k.begin() + 4);
  return k;
}

}  // namespace

TransactionId random_tid() {
  // thread_local: each thread gets its own generator, so no locking is needed.
  static thread_local std::mt19937 rng{std::random_device{}()};
  TransactionId tid{};
  for (auto& byte : tid) byte = static_cast<std::uint8_t>(rng());
  return tid;
}

std::vector<std::uint8_t> encode(const Message& m) {
  std::vector<std::uint8_t> body;
  if (m.xor_mapped) {
    const auto& ep = *m.xor_mapped;
    const bool v4 = ep.is_v4();
    put16(body, kAttrXorMappedAddress);
    put16(body, v4 ? 8 : 20);  // family(1)+reserved(1)+port(2)+address(4 or 16)
    body.push_back(0);
    body.push_back(v4 ? 0x01 : 0x02);
    // XOR with the magic cookie (and, for IPv6, the transaction ID) so NATs that rewrite IPs
    // inside payloads leave it alone.
    put16(body, static_cast<std::uint16_t>(ep.port ^ (kMagicCookie >> 16)));
    const auto key = xor_key(m.tid);
    if (v4) {
      for (int i = 0; i < 4; ++i) body.push_back(ep.ip[12 + i] ^ key[i]);
    } else {
      for (int i = 0; i < 16; ++i) body.push_back(ep.ip[i] ^ key[i]);
    }
  }
  if (m.change_request != 0) {
    put16(body, kAttrChangeRequest);
    put16(body, 4);
    put32(body, m.change_request);  // the flags sit in the low bits of a 32-bit value
  }
  std::vector<std::uint8_t> out;
  put16(out, m.type);
  put16(out, static_cast<std::uint16_t>(body.size()));
  put32(out, kMagicCookie);
  out.insert(out.end(), m.tid.begin(), m.tid.end());
  out.insert(out.end(), body.begin(), body.end());
  return out;
}

std::optional<Message> decode(std::span<const std::uint8_t> b) {
  if (b.size() < 20) return std::nullopt;
  if ((b[0] & 0xC0) != 0) return std::nullopt;  // first two bits must be 0
  if (get32(b, 4) != kMagicCookie) return std::nullopt;
  Message m;
  m.type = get16(b, 0);
  const std::size_t len = get16(b, 2);
  if (len % 4 != 0) return std::nullopt;  // attributes are 4-byte aligned
  if (b.size() < 20 + len) return std::nullopt;
  std::copy(b.begin() + 8, b.begin() + 20, m.tid.begin());

  std::size_t i = 20;
  while (i + 4 <= 20 + len) {
    const auto attr_type = get16(b, i);
    const auto attr_len = get16(b, i + 2);
    const std::size_t val = i + 4;
    if (val + attr_len > 20 + len) return std::nullopt;
    const bool xma = attr_type == kAttrXorMappedAddress;
    if (xma && ((attr_len == 8 && b[val + 1] == 0x01) || (attr_len == 20 && b[val + 1] == 0x02))) {
      const auto port = static_cast<std::uint16_t>(get16(b, val + 2) ^ (kMagicCookie >> 16));
      const auto key = xor_key(m.tid);
      if (attr_len == 8) {
        Ipv4 ip;
        for (int k = 0; k < 4; ++k) ip[k] = b[val + 4 + k] ^ key[k];
        m.xor_mapped = Endpoint{ip, port};
      } else {
        Ipv6 ip;
        for (int k = 0; k < 16; ++k) ip[k] = b[val + 4 + k] ^ key[k];
        m.xor_mapped = Endpoint::v6(ip, port);
      }
    } else if (attr_type == kAttrChangeRequest && attr_len == 4) {
      m.change_request = static_cast<std::uint8_t>(get32(b, val) & (kChangeIp | kChangePort));
    }
    i = val + ((attr_len + 3) & ~std::size_t{3});  // skip value + padding to 4 bytes
  }
  return m;
}

}  // namespace stun
