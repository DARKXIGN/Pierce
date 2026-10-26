#pragma once
#include <chrono>
#include <compare>
#include <cstdint>
#include <map>
#include <optional>
#include <unordered_map>

// The mapping/filtering logic of the symmetric-sequential lab NAT, kept free of sockets so it can be
// unit tested. All addresses and ports are in host byte order.
namespace usernat {

using Clock = std::chrono::steady_clock;

struct Endpoint {
  std::uint32_t ip = 0;
  std::uint16_t port = 0;
  auto operator<=>(const Endpoint&) const = default;
};

class Table {
 public:
  // Public ports are handed out from [port_min, port_max], each new mapping `step` above the last.
  // A mapping is removed after `lifetime` without traffic in either direction.
  Table(std::uint16_t port_min, std::uint16_t port_max, std::uint16_t step,
        std::chrono::seconds lifetime);

  // LAN -> WAN packet from `inner` to `remote`. Returns the public port to use as the new source,
  // creating a mapping if this (inner, remote) pair has none. nullopt if every port is in use.
  std::optional<std::uint16_t> outbound(Endpoint inner, Endpoint remote, Clock::time_point now);

  // WAN -> LAN packet from `remote` to `public_port`. Returns the LAN endpoint to deliver to, or
  // nullopt if the packet must be dropped: there is no such mapping, or it was made for a different
  // remote ip:port (address-and-port-dependent filtering).
  std::optional<Endpoint> inbound(std::uint16_t public_port, Endpoint remote,
                                  Clock::time_point now);

  // Remove mappings idle for longer than the lifetime. Returns how many were removed.
  std::size_t expire(Clock::time_point now);

  std::size_t size() const { return by_port_.size(); }

 private:
  struct Mapping {
    Endpoint inner, remote;
    Clock::time_point last_used;
  };

  std::uint16_t advance(std::uint16_t port) const;

  std::uint16_t port_min_, port_max_, step_;
  std::chrono::seconds lifetime_;
  std::uint16_t next_;
  // Two indexes over the same mappings: by flow for outbound, by public port for inbound.
  std::map<std::pair<Endpoint, Endpoint>, std::uint16_t> by_flow_;
  std::unordered_map<std::uint16_t, Mapping> by_port_;
};

}  // namespace usernat
