#include "wg/tunnel.hpp"

#include <openssl/evp.h>

#include <stdexcept>

extern "C" {
#include "third_party/boringtun/wireguard_ffi.h"
}

namespace wg {
namespace {

std::string to_base64(const x25519_key& k) {
  const char* s = x25519_key_to_base64(k);
  std::string out = s ? s : "";
  x25519_key_to_str_free(s);
  return out;
}

// Base64 decoding is plain encoding, not cryptography; OpenSSL does it for us.
std::optional<x25519_key> from_base64(std::string_view b64) {
  if (b64.size() != 44) return std::nullopt;  // 32 bytes -> 44 base64 characters with padding
  unsigned char out[33] = {};                  // EVP_DecodeBlock writes 33 bytes for 44 chars
  if (EVP_DecodeBlock(out, reinterpret_cast<const unsigned char*>(b64.data()), 44) != 33)
    return std::nullopt;
  x25519_key k{};
  std::copy(out, out + 32, k.key);
  return k;
}

}  // namespace

std::string generate_private_key() { return to_base64(x25519_secret_key()); }

std::optional<std::string> public_key(std::string_view private_key_base64) {
  auto k = from_base64(private_key_base64);
  if (!k || !valid_key(private_key_base64)) return std::nullopt;
  return to_base64(x25519_public_key(*k));
}

bool valid_key(std::string_view key_base64) {
  return check_base64_encoded_x25519_key(std::string(key_base64).c_str()) != 0;
}

bool looks_like_wireguard(std::span<const std::uint8_t> b) {
  return b.size() >= 4 && b[0] >= 1 && b[0] <= 4 && b[1] == 0 && b[2] == 0 && b[3] == 0;
}

Tunnel::Tunnel(const std::string& my_private_key, const std::string& peer_public_key,
               std::uint16_t keepalive_s, std::uint32_t index)
    : buf_(MAX_WIREGUARD_PACKET_SIZE) {
  if (!valid_key(my_private_key) || !valid_key(peer_public_key))
    throw std::invalid_argument("not a valid WireGuard key");
  t_ = new_tunnel(my_private_key.c_str(), peer_public_key.c_str(), nullptr, keepalive_s, index);
  if (!t_) throw std::runtime_error("BoringTun new_tunnel failed");
}

Tunnel::~Tunnel() {
  if (t_) tunnel_free(t_);
}

Tunnel::Output Tunnel::wrap(int op, std::size_t size) {
  Output o;
  switch (op) {
    case WIREGUARD_DONE: o.op = Op::Done; return o;
    case WRITE_TO_NETWORK: o.op = Op::ToNetwork; break;
    case WRITE_TO_TUNNEL_IPV4:
    case WRITE_TO_TUNNEL_IPV6: o.op = Op::ToTunnel; break;
    default: o.op = Op::Error; return o;
  }
  o.data = std::span<const std::uint8_t>(buf_.data(), size);
  return o;
}

Tunnel::Output Tunnel::encapsulate(std::span<const std::uint8_t> ip_packet) {
  auto r = wireguard_write(t_, ip_packet.data(), static_cast<std::uint32_t>(ip_packet.size()),
                           buf_.data(), static_cast<std::uint32_t>(buf_.size()));
  return wrap(r.op, r.size);
}

Tunnel::Output Tunnel::decapsulate(std::span<const std::uint8_t> datagram) {
  auto r = wireguard_read(t_, datagram.data(), static_cast<std::uint32_t>(datagram.size()),
                          buf_.data(), static_cast<std::uint32_t>(buf_.size()));
  return wrap(r.op, r.size);
}

Tunnel::Output Tunnel::flush() {
  auto r = wireguard_read(t_, nullptr, 0, buf_.data(), static_cast<std::uint32_t>(buf_.size()));
  return wrap(r.op, r.size);
}

Tunnel::Output Tunnel::tick() {
  auto r = wireguard_tick(t_, buf_.data(), static_cast<std::uint32_t>(buf_.size()));
  return wrap(r.op, r.size);
}

Tunnel::Output Tunnel::force_handshake() {
  auto r = wireguard_force_handshake(t_, buf_.data(), static_cast<std::uint32_t>(buf_.size()));
  return wrap(r.op, r.size);
}

}  // namespace wg
