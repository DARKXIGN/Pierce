#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

// Connectivity-check probes. They share the UDP socket with WireGuard (stage 4) and STUN, and are
// told apart by the first byte: WireGuard uses 1-4, STUN 0x00/0x01, probes 0xFF.
//
//   0xFF | version (1) | transaction ID (12) | kind (1) | HMAC (8)        = 23 bytes
//
// HMAC-SHA256 over everything before it, truncated to 8 bytes, keyed with the per-session key both
// peers get from the coordination server. Without the key an off-path attacker cannot forge a
// probe that makes us pick a path.
namespace probe {

constexpr std::uint8_t kMagic = 0xFF;
constexpr std::uint8_t kVersion = 1;
constexpr std::size_t kSize = 23;
constexpr std::size_t kMacSize = 8;

enum class Kind : std::uint8_t { Request = 1, Response = 2 };

using TransactionId = std::array<std::uint8_t, 12>;
using Key = std::vector<std::uint8_t>;

struct Probe {
  Kind kind = Kind::Request;
  TransactionId tid{};
};

TransactionId random_tid();  // from OpenSSL's CSPRNG: unguessable, unlike std::mt19937

// HMAC-SHA256(key, data) truncated to its first 8 bytes. Exposed for tests.
std::array<std::uint8_t, kMacSize> mac8(std::span<const std::uint8_t> data, const Key& key);

std::array<std::uint8_t, kSize> encode(const Probe& p, const Key& key);

// nullopt if it is not a probe, has an unknown version or kind, or the HMAC does not match.
std::optional<Probe> decode(std::span<const std::uint8_t> bytes, const Key& key);

inline bool looks_like_probe(std::span<const std::uint8_t> bytes) {
  return !bytes.empty() && bytes[0] == kMagic;
}

}  // namespace probe
