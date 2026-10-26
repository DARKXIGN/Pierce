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
    put16(body, kAttrXorMappedAddress);
    put16(body, 8);  // family(1)+reserved(1)+port(2)+ipv4(4)
    body.push_back(0);
    body.push_back(0x01);  // IPv4
    // XOR with the magic cookie so NATs that rewrite IPs inside payloads leave it alone.
    put16(body, static_cast<std::uint16_t>(ep.port ^ (kMagicCookie >> 16)));
    const std::uint32_t ip = (static_cast<std::uint32_t>(ep.ipv4[0]) << 24) |
                             (static_cast<std::uint32_t>(ep.ipv4[1]) << 16) |
                             (static_cast<std::uint32_t>(ep.ipv4[2]) << 8) | ep.ipv4[3];
    put32(body, ip ^ kMagicCookie);
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
    if (attr_type == kAttrXorMappedAddress && attr_len == 8 && b[val + 1] == 0x01) {
      Endpoint ep;
      ep.port = static_cast<std::uint16_t>(get16(b, val + 2) ^ (kMagicCookie >> 16));
      const std::uint32_t ip = get32(b, val + 4) ^ kMagicCookie;
      ep.ipv4 = {static_cast<std::uint8_t>(ip >> 24), static_cast<std::uint8_t>(ip >> 16),
                 static_cast<std::uint8_t>(ip >> 8), static_cast<std::uint8_t>(ip)};
      m.xor_mapped = ep;
    } else if (attr_type == kAttrChangeRequest && attr_len == 4) {
      m.change_request = static_cast<std::uint8_t>(get32(b, val) & (kChangeIp | kChangePort));
    }
    i = val + ((attr_len + 3) & ~std::size_t{3});  // skip value + padding to 4 bytes
  }
  return m;
}

}  // namespace stun
