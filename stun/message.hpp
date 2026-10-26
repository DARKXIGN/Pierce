#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

// STUN Binding only (RFC 8489 §5, §14.2). Enough for NAT detection; not a full STUN stack.
// Unknown attributes are skipped on decode; MESSAGE-INTEGRITY and FINGERPRINT are not checked.
namespace stun {

constexpr std::uint32_t kMagicCookie = 0x2112A442;
constexpr std::uint16_t kBindingRequest = 0x0001;
constexpr std::uint16_t kBindingResponse = 0x0101;
constexpr std::uint16_t kAttrXorMappedAddress = 0x0020;

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
};

TransactionId random_tid();
std::vector<std::uint8_t> encode(const Message& m);
std::optional<Message> decode(std::span<const std::uint8_t> bytes);

}  // namespace stun
