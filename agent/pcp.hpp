#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <span>

// PCP (Port Control Protocol, RFC 6887) MAP messages, our own implementation as the design asks.
// Just what a client needs to map one UDP port on its IPv4 gateway (server port 5351).
namespace pcp {

constexpr std::uint16_t kServerPort = 5351;
constexpr std::size_t kMapSize = 60;  // 24-byte common header + 36-byte MAP opcode data
using Nonce = std::array<std::uint8_t, 12>;
using Ipv4 = std::array<std::uint8_t, 4>;

struct MapRequest {
  Ipv4 client_ip{};               // our address as the server sees it (else ADDRESS_MISMATCH)
  std::uint16_t internal_port = 0;
  std::uint16_t suggested_external_port = 0;
  std::uint32_t lifetime_s = 0;   // 0 deletes the mapping
  Nonce nonce{};                  // identifies the mapping; the response must echo it
};

struct MapResponse {
  std::uint8_t result = 0;  // 0 = SUCCESS
  std::uint32_t lifetime_s = 0;
  std::uint16_t internal_port = 0;
  std::uint16_t external_port = 0;
  Ipv4 external_ip{};
};

std::array<std::uint8_t, kMapSize> encode(const MapRequest& r);
// nullopt unless `bytes` is a MAP response for UDP with this nonce.
std::optional<MapResponse> decode(std::span<const std::uint8_t> bytes, const Nonce& nonce);

}  // namespace pcp
