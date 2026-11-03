#pragma once
#include <cstdint>
#include <optional>
#include <span>

#include "lab/usernat/nat_table.hpp"

// Just enough IPv4/UDP handling to rewrite addresses: parse, rewrite, recompute checksums.
namespace usernat {

struct UdpHeaderInfo {
  Endpoint src, dst;
};

// Parses an IPv4 packet that carries a complete, unfragmented UDP datagram. nullopt otherwise.
std::optional<UdpHeaderInfo> parse_udp(std::span<const std::uint8_t> pkt);

// Overwrite the source or destination ip:port of a packet parse_udp accepted, decrement the TTL and
// recompute both checksums. Returns false if the TTL ran out (the packet must be dropped).
bool rewrite_src(std::span<std::uint8_t> pkt, Endpoint src);
bool rewrite_dst(std::span<std::uint8_t> pkt, Endpoint dst);

// RFC 1071 Internet checksum, exposed for tests.
std::uint16_t inet_checksum(std::span<const std::uint8_t> data, std::uint32_t initial = 0);

}  // namespace usernat
