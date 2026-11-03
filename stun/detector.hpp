#pragma once
#include <chrono>
#include <optional>
#include <string_view>
#include <vector>

#include "stun/message.hpp"
#include "stun/udp.hpp"

// NAT type detection against one STUN server that has two IPs and two ports (RFC 5780 style).
namespace stun {

enum class NatType { Full, Restricted, PortRestricted, SymmetricRandom, SymmetricSequential, Unknown };

// The lab's names: full | restricted | port-restricted | symmetric-random | symmetric-sequential.
// Unknown ("no-response") means the server did not answer the mapping requests.
std::string_view to_string(NatType t);

// What the detector saw. Kept separate from the network code so classify() can be unit tested.
struct Observations {
  // Public endpoints the server saw for ONE local socket sending to three destinations:
  // primary ip:port, alternate ip:same port, primary ip:alternate port.
  std::optional<Endpoint> mapped_primary, mapped_alt_ip, mapped_alt_port;
  // From a fresh socket that has only talked to the primary address: did a response sent
  // from the other IP (resp. from the other port) get through the NAT?
  bool reached_from_other_ip = false;
  bool reached_from_other_port = false;
};

// Mapping first: the public port changing with the destination means symmetric. Sequential if
// the three mappings move by the same small step (e.g. +1, +1), random otherwise. Cone NATs are
// then told apart by their filtering.
NatType classify(const Observations& o);

struct DetectorConfig {
  Endpoint server;                    // primary ip:port
  std::array<std::uint8_t, 4> alt_ip{};
  std::uint16_t alt_port = 3479;
  std::chrono::milliseconds timeout{200};  // wait per try
  int tries = 3;                           // transmissions per request
};

class Detector {
 public:
  explicit Detector(DetectorConfig cfg) : cfg_(cfg) {}
  Observations observe();
  NatType detect() { return classify(observe()); }

 private:
  std::optional<Message> transact(UdpSocket& sock, const Endpoint& to, std::uint8_t change);
  UdpSocket& fresh_socket();

  DetectorConfig cfg_;
  // Every socket stays open until the Detector is destroyed. Otherwise the kernel could hand the
  // same local port to the next run, and NAT state left from the earlier run would skew it.
  std::vector<UdpSocket> sockets_;
};

}  // namespace stun
