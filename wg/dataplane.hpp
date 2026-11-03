#pragma once
#include <chrono>
#include <cstdint>

#include "agent/probe.hpp"
#include "stun/udp.hpp"
#include "wg/tun.hpp"
#include "wg/tunnel.hpp"

// The data plane: TUN <-> WireGuard (BoringTun) <-> the UDP socket the connection was made on.
// That socket keeps carrying probes too (the peer may still be probing when we start), told
// apart by the first byte: WireGuard 1-4, probe 0xFF; anything else is dropped.
namespace wg {

struct DataPlaneStats {
  std::uint64_t to_peer = 0;    // IP packets from the TUN device, encrypted and sent
  std::uint64_t from_peer = 0;  // WireGuard packets decrypted and written to the TUN device
  std::uint64_t dropped = 0;    // datagrams that were not for us or failed to decrypt
};

class DataPlane {
 public:
  // `peer` is where WireGuard packets go: the peer's address on a direct path, the relay's on a
  // relayed one. Datagrams are only accepted from that IP.
  DataPlane(Tun& tun, Tunnel& tunnel, stun::UdpSocket& sock, stun::Endpoint peer, probe::Key key)
      : tun_(tun), tunnel_(tunnel), sock_(sock), peer_(peer), key_(std::move(key)) {}

  // Moves packets until `until`. Starts the WireGuard handshake right away.
  DataPlaneStats run(std::chrono::steady_clock::time_point until);

 private:
  void send(std::span<const std::uint8_t> datagram);
  void from_network(const stun::Datagram& d);

  Tun& tun_;
  Tunnel& tunnel_;
  stun::UdpSocket& sock_;
  stun::Endpoint peer_;
  probe::Key key_;
  DataPlaneStats stats_;
};

}  // namespace wg
