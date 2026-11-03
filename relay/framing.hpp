#pragma once
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "stun/message.hpp"

// Datagrams over a byte stream (the TCP/TLS fallback to the relay, for networks that block UDP):
// each datagram is sent as a 2-byte big-endian length followed by the bytes, unchanged. Inside
// the stream the relay protocol is exactly the UDP one (relay/protocol.hpp).
namespace relay {

std::vector<std::uint8_t> frame(std::span<const std::uint8_t> datagram);

// Collects stream bytes and hands back complete datagrams.
class Deframer {
 public:
  void feed(std::span<const std::uint8_t> bytes) { buf_.insert(buf_.end(), bytes.begin(), bytes.end()); }
  std::optional<std::vector<std::uint8_t>> next();

 private:
  std::vector<std::uint8_t> buf_;
};

// The relay's forwarding table is keyed by endpoint. A TCP/TLS client has none that the table
// could send UDP to, so it gets a stand-in that no real UDP source can have: 0.a.b.c:0, where
// a.b.c is the connection's id.
stun::Endpoint stream_endpoint(std::uint32_t id);
std::optional<std::uint32_t> stream_id(const stun::Endpoint& ep);

}  // namespace relay
