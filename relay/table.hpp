#pragma once
#include <chrono>
#include <map>
#include <optional>
#include <span>
#include <vector>

#include "relay/protocol.hpp"
#include "stun/message.hpp"

// The relay's forwarding logic, free of sockets so it can be unit tested.
namespace relay {

using stun::Endpoint;

struct Outgoing {
  std::vector<std::uint8_t> bytes;
  Endpoint to;
};

class Table {
 public:
  Table(Secret secret, std::chrono::seconds idle_timeout)
      : secret_(std::move(secret)), idle_(idle_timeout) {}

  // One datagram from `from`, received at unix time `now`. Returns what to send in reply, if
  // anything: BOUND, PONG, or the datagram forwarded to the session's other endpoint.
  std::optional<Outgoing> handle(std::span<const std::uint8_t> bytes, const Endpoint& from,
                                 std::uint64_t now);

  // Drop sessions whose token expired or that were idle longer than the timeout.
  void expire(std::uint64_t now);

  std::size_t sessions() const { return sessions_.size(); }

 private:
  struct Slot {
    Endpoint ep;
    std::uint64_t last_seen = 0;
  };
  struct Session {
    std::vector<Slot> slots;  // at most 2: the two peers
    std::uint64_t expires = 0;
  };

  Secret secret_;
  std::chrono::seconds idle_;
  std::map<SessionId, Session> sessions_;
  std::map<Endpoint, SessionId> by_endpoint_;
};

}  // namespace relay
