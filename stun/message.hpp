#pragma once
#include <algorithm>
#include <array>
#include <compare>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

// STUN Binding only (RFC 8489 §5, §14.2), plus CHANGE-REQUEST from RFC 5780 §7.2 so the detector
// can ask for a reply from another IP or port (that is how inbound filtering is tested).
// Not a full STUN stack: unknown attributes are skipped on decode; MESSAGE-INTEGRITY and
// FINGERPRINT are not checked.
namespace stun {

constexpr std::uint32_t kMagicCookie = 0x2112A442;
constexpr std::uint16_t kBindingRequest = 0x0001;
constexpr std::uint16_t kBindingResponse = 0x0101;
constexpr std::uint16_t kAttrChangeRequest = 0x0003;
constexpr std::uint16_t kAttrXorMappedAddress = 0x0020;

// CHANGE-REQUEST flags: "send the response from the other IP" / "from the other port".
constexpr std::uint8_t kChangeIp = 0x04;
constexpr std::uint8_t kChangePort = 0x02;

using TransactionId = std::array<std::uint8_t, 12>;

using Ipv4 = std::array<std::uint8_t, 4>;
using Ipv6 = std::array<std::uint8_t, 16>;

// An IP address and port, IPv4 or IPv6. The address is always 16 bytes: IPv6 as it is, IPv4 in
// IPv4-mapped form ::ffff:a.b.c.d (RFC 4291 §2.5.5.2). That is also how a dual-stack socket
// reports IPv4 peers, so one socket and one Endpoint type cover both families.
struct Endpoint {
  Ipv6 ip{};  // all zero = "::", any address (IPv4 and IPv6)
  std::uint16_t port = 0;

  Endpoint() = default;
  // From an IPv4 address: Endpoint{{192, 0, 2, 1}, 3478}. (No second constructor for IPv6: a
  // short brace list like {192, 0, 2, 1} would fit a 16-byte array too and be ambiguous.)
  Endpoint(const Ipv4& v4, std::uint16_t p) : port(p) {
    ip[10] = ip[11] = 0xFF;
    std::copy(v4.begin(), v4.end(), ip.begin() + 12);
  }
  static Endpoint v6(const Ipv6& a, std::uint16_t p) {
    Endpoint e;
    e.ip = a;
    e.port = p;
    return e;
  }

  bool is_v4() const {
    return std::all_of(ip.begin(), ip.begin() + 10, [](std::uint8_t b) { return b == 0; }) &&
           ip[10] == 0xFF && ip[11] == 0xFF;
  }
  Ipv4 v4() const { return {ip[12], ip[13], ip[14], ip[15]}; }  // only meaningful if is_v4()
  bool same_ip(const Endpoint& o) const { return ip == o.ip; }

  auto operator<=>(const Endpoint&) const = default;  // ==, <, ... (e.g. as a std::map key)
};

struct Message {
  std::uint16_t type = 0;
  TransactionId tid{};
  std::optional<Endpoint> xor_mapped;
  std::uint8_t change_request = 0;  // kChangeIp | kChangePort; 0 = attribute absent
};

TransactionId random_tid();
std::vector<std::uint8_t> encode(const Message& m);
std::optional<Message> decode(std::span<const std::uint8_t> bytes);

}  // namespace stun
