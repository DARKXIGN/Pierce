#pragma once
#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "stun/message.hpp"

// Asking the home router to open a port for us (pipeline step 3: port mapping candidates). A
// mapped port takes packets from anyone, so it gets through even a symmetric NAT. Three
// protocols, tried in order: PCP (RFC 6887, our implementation), NAT-PMP (RFC 6886, libnatpmp),
// UPnP IGD (miniupnpc).
namespace agent {

enum class PortMapProtocol { Pcp, NatPmp, Upnp };
std::string_view to_string(PortMapProtocol p);
// "auto" = pcp,natpmp,upnp; "off" = none; or one name. nullopt for anything else.
std::optional<std::vector<PortMapProtocol>> parse_portmap(std::string_view s);

// The IPv4 default gateway from /proc/net/route.
std::optional<std::array<std::uint8_t, 4>> default_gateway();

class PortMapping {
 public:
  // Tries each protocol in order for UDP `internal_port` until one works or `budget` runs out.
  // Each is quick when nothing listens (the gateway answers with ICMP port unreachable).
  static std::optional<PortMapping> create(std::uint16_t internal_port,
                                           const std::vector<PortMapProtocol>& order,
                                           std::chrono::milliseconds budget,
                                           std::uint32_t lifetime_s = 7200);
  ~PortMapping();  // removes the mapping from the router
  PortMapping(PortMapping&& other) noexcept;
  PortMapping& operator=(PortMapping&&) = delete;
  PortMapping(const PortMapping&) = delete;

  PortMapProtocol protocol() const { return protocol_; }
  stun::Endpoint external() const { return external_; }

 private:
  PortMapping() = default;
  PortMapProtocol protocol_ = PortMapProtocol::Pcp;
  stun::Endpoint external_;
  std::uint16_t internal_port_ = 0;
  std::array<std::uint8_t, 4> gateway_{};
  std::array<std::uint8_t, 4> client_ip_{};
  std::array<std::uint8_t, 12> pcp_nonce_{};
  std::string upnp_control_url_, upnp_service_type_;
  bool active_ = false;
};

}  // namespace agent
