#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

// Relay wire format. Relay control packets start with 0xFE, which no other packet on the agent's
// socket uses (WireGuard 1-4, STUN 0x00/0x01, probes 0xFF). Everything else a bound endpoint sends
// is forwarded unchanged, so the relay only ever sees WireGuard ciphertext and probes.
//
//   BIND   0xFE 0x01 token(40)   "forward between me and the other holder of this token"
//   BOUND  0xFE 0x02             reply to a valid BIND
//   PING   0xFE 0x03 nonce(8)    RTT measurement; anyone may ask
//   PONG   0xFE 0x04 nonce(8)    same size as PING, so no amplification
//
// Token (issued by the coordination server, checked by the relay without asking it):
//   session id (16) | expiry, unix seconds, big endian (8) | HMAC-SHA256(secret, first 24)[:16]
// The relay and the coordination server share `secret`. Because the relay needs nothing else, a
// relayed connection keeps working while the coordination server is down, until expiry.
namespace relay {

constexpr std::uint8_t kMagic = 0xFE;
enum class Type : std::uint8_t { Bind = 1, Bound = 2, Ping = 3, Pong = 4 };

constexpr std::size_t kTokenSize = 40;
using SessionId = std::array<std::uint8_t, 16>;
using TokenBytes = std::array<std::uint8_t, kTokenSize>;
using Secret = std::vector<std::uint8_t>;

struct Token {
  SessionId session{};
  std::uint64_t expires = 0;  // unix seconds
};

TokenBytes issue_token(const Token& t, const Secret& secret);
// nullopt if the MAC is wrong or the token has expired at `now` (unix seconds).
std::optional<Token> verify_token(std::span<const std::uint8_t> bytes, const Secret& secret,
                                  std::uint64_t now);

std::vector<std::uint8_t> bind_message(const TokenBytes& token);
std::vector<std::uint8_t> bound_message();
std::vector<std::uint8_t> ping_message(std::uint64_t nonce);

inline bool is_control(std::span<const std::uint8_t> b) { return b.size() >= 2 && b[0] == kMagic; }
inline std::optional<Type> control_type(std::span<const std::uint8_t> b) {
  if (!is_control(b) || b[1] < 1 || b[1] > 4) return std::nullopt;
  return static_cast<Type>(b[1]);
}
// "5a5a..." -> bytes. nullopt for odd length, empty input or a non-hex digit.
std::optional<Secret> secret_from_hex(std::string_view hex);

// The nonce of a PING or PONG.
std::optional<std::uint64_t> nonce_of(std::span<const std::uint8_t> b);

}  // namespace relay
