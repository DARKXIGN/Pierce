#include "lab/usernat/packet.hpp"

namespace usernat {
namespace {

// IPv4 header offsets (RFC 791) and the UDP header that follows it (RFC 768).
constexpr std::size_t kIpTtl = 8, kIpProto = 9, kIpChecksum = 10, kIpSrc = 12, kIpDst = 16;
constexpr std::size_t kUdpSrcPort = 0, kUdpDstPort = 2, kUdpLen = 4, kUdpChecksum = 6;
constexpr std::uint8_t kProtoUdp = 17;

std::uint16_t get16(std::span<const std::uint8_t> b, std::size_t i) {
  return static_cast<std::uint16_t>((b[i] << 8) | b[i + 1]);
}
std::uint32_t get32(std::span<const std::uint8_t> b, std::size_t i) {
  return (std::uint32_t{get16(b, i)} << 16) | get16(b, i + 2);
}
void put16(std::span<std::uint8_t> b, std::size_t i, std::uint16_t v) {
  b[i] = static_cast<std::uint8_t>(v >> 8);
  b[i + 1] = static_cast<std::uint8_t>(v);
}
void put32(std::span<std::uint8_t> b, std::size_t i, std::uint32_t v) {
  put16(b, i, static_cast<std::uint16_t>(v >> 16));
  put16(b, i + 2, static_cast<std::uint16_t>(v));
}

std::size_t ip_header_len(std::span<const std::uint8_t> pkt) { return (pkt[0] & 0x0F) * 4u; }

// Recompute both checksums after the header was changed.
void fix_checksums(std::span<std::uint8_t> pkt) {
  const std::size_t ihl = ip_header_len(pkt);
  put16(pkt, kIpChecksum, 0);
  put16(pkt, kIpChecksum, inet_checksum(pkt.first(ihl)));

  auto udp = pkt.subspan(ihl, get16(pkt, ihl + kUdpLen));
  // A zero UDP checksum means "sender did not compute one" in IPv4; keep it that way.
  if (get16(udp, kUdpChecksum) == 0) return;
  // The UDP checksum also covers a "pseudo-header": source IP, destination IP, protocol, length.
  std::uint32_t pseudo = get16(pkt, kIpSrc) + get16(pkt, kIpSrc + 2) + get16(pkt, kIpDst) +
                         get16(pkt, kIpDst + 2) + kProtoUdp + static_cast<std::uint32_t>(udp.size());
  put16(udp, kUdpChecksum, 0);
  std::uint16_t sum = inet_checksum(udp, pseudo);
  put16(udp, kUdpChecksum, sum == 0 ? 0xFFFF : sum);  // 0 is reserved for "no checksum"
}

bool decrement_ttl(std::span<std::uint8_t> pkt) {
  if (pkt[kIpTtl] <= 1) return false;
  --pkt[kIpTtl];
  return true;
}

}  // namespace

std::uint16_t inet_checksum(std::span<const std::uint8_t> data, std::uint32_t initial) {
  std::uint32_t sum = initial;
  std::size_t i = 0;
  for (; i + 1 < data.size(); i += 2) sum += get16(data, i);
  if (i < data.size()) sum += std::uint32_t{data[i]} << 8;  // odd length: pad with a zero byte
  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);   // fold the carries back in
  return static_cast<std::uint16_t>(~sum);
}

std::optional<UdpHeaderInfo> parse_udp(std::span<const std::uint8_t> pkt) {
  if (pkt.size() < 20 || (pkt[0] >> 4) != 4) return std::nullopt;
  const std::size_t ihl = ip_header_len(pkt);
  const std::size_t total = get16(pkt, 2);
  if (ihl < 20 || total > pkt.size() || total < ihl + 8) return std::nullopt;
  if (pkt[kIpProto] != kProtoUdp) return std::nullopt;
  // Fragments (MF flag set or non-zero offset) would need reassembly; the lab never sends them.
  if ((get16(pkt, 6) & 0x3FFF) != 0) return std::nullopt;
  if (get16(pkt, ihl + kUdpLen) != total - ihl) return std::nullopt;
  return UdpHeaderInfo{{get32(pkt, kIpSrc), get16(pkt, ihl + kUdpSrcPort)},
                       {get32(pkt, kIpDst), get16(pkt, ihl + kUdpDstPort)}};
}

bool rewrite_src(std::span<std::uint8_t> pkt, Endpoint src) {
  if (!decrement_ttl(pkt)) return false;
  put32(pkt, kIpSrc, src.ip);
  put16(pkt, ip_header_len(pkt) + kUdpSrcPort, src.port);
  fix_checksums(pkt);
  return true;
}

bool rewrite_dst(std::span<std::uint8_t> pkt, Endpoint dst) {
  if (!decrement_ttl(pkt)) return false;
  put32(pkt, kIpDst, dst.ip);
  put16(pkt, ip_header_len(pkt) + kUdpDstPort, dst.port);
  fix_checksums(pkt);
  return true;
}

}  // namespace usernat
