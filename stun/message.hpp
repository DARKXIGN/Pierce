#pragma once
#include <array>
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

struct Endpoint {
  std::array<std::uint8_t, 4> ipv4{};  // IPv4 only for now
  std::uint16_t port = 0;
  bool operator==(const Endpoint&) const = default;
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
