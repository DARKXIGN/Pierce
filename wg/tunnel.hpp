#pragma once
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

struct wireguard_tunnel;  // BoringTun's opaque tunnel type (third_party/boringtun/wireguard_ffi.h)

// C++ wrapper around BoringTun's C API: one WireGuard tunnel to one peer. All of WireGuard's
// cryptography (Noise handshake, ChaCha20-Poly1305) happens inside BoringTun; this class only
// moves bytes in and out.
namespace wg {

// x25519 keys as base64 text, the format `wg` uses and BoringTun accepts.
std::string generate_private_key();
std::optional<std::string> public_key(std::string_view private_key_base64);
bool valid_key(std::string_view key_base64);

// True for WireGuard messages: type 1-4 followed by three zero bytes. Probes start with 0xFF,
// STUN with 0x00/0x01 then the rest of a STUN header, relay control with 0xFE.
bool looks_like_wireguard(std::span<const std::uint8_t> bytes);

class Tunnel {
 public:
  enum class Op {
    Done,        // nothing to do
    ToNetwork,   // send `data` to the peer over UDP
    ToTunnel,    // write `data` (an IP packet) to the TUN device
    Error,
  };
  struct Output {
    Op op = Op::Done;
    std::span<const std::uint8_t> data;  // valid until the next call on this Tunnel
  };

  // keepalive_s: WireGuard persistent keepalive (0 = off). index: 24-bit session index prefix.
  // Throws std::invalid_argument if a key is not valid.
  Tunnel(const std::string& my_private_key, const std::string& peer_public_key,
         std::uint16_t keepalive_s, std::uint32_t index = 0);
  ~Tunnel();
  Tunnel(const Tunnel&) = delete;
  Tunnel& operator=(const Tunnel&) = delete;

  // An IP packet from the TUN device -> usually ToNetwork (encrypted), or a handshake first.
  Output encapsulate(std::span<const std::uint8_t> ip_packet);
  // A WireGuard datagram from the network -> ToTunnel (decrypted packet), or ToNetwork (e.g. a
  // handshake response). After ToNetwork, call flush() until it returns Done: BoringTun may have
  // queued packets that waited for the handshake.
  Output decapsulate(std::span<const std::uint8_t> datagram);
  Output flush();
  // Call about every 100 ms: retransmits handshakes, sends keepalives.
  Output tick();
  // Start a handshake now instead of on the first packet.
  Output force_handshake();

 private:
  Output wrap(int op, std::size_t size);

  wireguard_tunnel* t_ = nullptr;
  std::vector<std::uint8_t> buf_;
};

}  // namespace wg
