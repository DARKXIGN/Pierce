#include "agent/pcp.hpp"

#include <algorithm>

namespace pcp {
namespace {

constexpr std::uint8_t kVersion = 2, kOpMap = 1, kResponseBit = 0x80, kProtoUdp = 17;

void put16(std::uint8_t* p, std::uint16_t v) { p[0] = std::uint8_t(v >> 8); p[1] = std::uint8_t(v); }
void put32(std::uint8_t* p, std::uint32_t v) { put16(p, std::uint16_t(v >> 16)); put16(p + 2, std::uint16_t(v)); }
std::uint16_t get16(const std::uint8_t* p) { return std::uint16_t((p[0] << 8) | p[1]); }
std::uint32_t get32(const std::uint8_t* p) { return (std::uint32_t{get16(p)} << 16) | get16(p + 2); }

// PCP carries every address as 16 bytes; IPv4 goes in IPv4-mapped IPv6 form, ::ffff:a.b.c.d.
void put_v4mapped(std::uint8_t* p, const Ipv4& ip) {
  std::fill(p, p + 10, 0);
  p[10] = p[11] = 0xFF;
  std::copy(ip.begin(), ip.end(), p + 12);
}

}  // namespace

std::array<std::uint8_t, kMapSize> encode(const MapRequest& r) {
  std::array<std::uint8_t, kMapSize> b{};
  // Common request header (RFC 6887 §7.1): version, R=0 | opcode, reserved, lifetime, client IP.
  b[0] = kVersion;
  b[1] = kOpMap;
  put32(&b[4], r.lifetime_s);
  put_v4mapped(&b[8], r.client_ip);
  // MAP opcode data (§11.1): nonce, protocol, reserved, internal port, suggested external port,
  // suggested external IP (all zero: "any").
  std::copy(r.nonce.begin(), r.nonce.end(), &b[24]);
  b[36] = kProtoUdp;
  put16(&b[40], r.internal_port);
  put16(&b[42], r.suggested_external_port);
  return b;
}

std::optional<MapResponse> decode(std::span<const std::uint8_t> b, const Nonce& nonce) {
  if (b.size() < kMapSize || b[0] != kVersion || b[1] != (kResponseBit | kOpMap)) return std::nullopt;
  if (!std::equal(nonce.begin(), nonce.end(), &b[24]) || b[36] != kProtoUdp) return std::nullopt;
  MapResponse r;
  r.result = b[3];
  r.lifetime_s = get32(&b[4]);
  r.internal_port = get16(&b[40]);
  r.external_port = get16(&b[42]);
  std::copy(&b[56], &b[60], r.external_ip.begin());  // last 4 bytes of ::ffff:a.b.c.d
  return r;
}

}  // namespace pcp
