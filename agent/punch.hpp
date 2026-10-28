#pragma once
#include <chrono>
#include <optional>
#include <vector>

#include "agent/candidates.hpp"
#include "agent/probe.hpp"
#include "stun/udp.hpp"

// Connectivity checks: both peers probe each other's candidates at the same moment, so each NAT
// sees an outgoing packet to the other side and opens a mapping for the replies ("hole punching").
namespace agent {

using Clock = std::chrono::steady_clock;

struct PunchOptions {
  // One probe request per interval, round robin over every (local socket, remote address) pair.
  // With many pairs the interval shrinks so that one full pass takes at most `pass` (but never
  // below 1 ms), otherwise 256 birthday probes would take longer than the whole attempt.
  std::chrono::milliseconds interval{20};
  std::chrono::milliseconds pass{500};
  std::chrono::milliseconds timeout{3000};  // give up on the direct path after this
  // After we are connected, keep answering the peer's requests until it has been quiet this long,
  // so the peer can finish too.
  std::chrono::milliseconds linger{300};
};

struct PunchResult {
  bool success = false;
  Clock::time_point connected_at{};
  std::optional<Endpoint> path;  // the remote address that answered our probe
  std::size_t local = 0;         // which local socket it answered on (0 = the main socket)
};

struct HoldStats {
  int sent = 0;
  int answered = 0;
};

class Puncher {
 public:
  // `remote` comes from signaling. Probes are only ever sent to IPs in that list.
  Puncher(stun::UdpSocket& main, probe::Key key, std::vector<Candidate> remote);

  // Birthday probing, hard side: every socket in `extra` probes only `target` (the peer's one
  // public endpoint). Behind a NAT that picks a random public port per socket and destination,
  // that gives `extra.size()` different public ports toward the peer, any of which the peer may
  // hit with its guesses. The sockets must outlive the Puncher.
  void add_birthday_sockets(std::vector<stun::UdpSocket>& extra, const Endpoint& target);

  PunchResult connect(const PunchOptions& opt);

  // Keepalive on an established path: one request per `interval` for `duration`, answering the
  // peer's requests in between. Needs no coordination server.
  HoldStats hold(std::size_t local, const Endpoint& path, std::chrono::milliseconds duration,
                 std::chrono::milliseconds interval);

  int probes_sent() const { return sent_; }
  const std::vector<Candidate>& remote() const { return remote_; }

 private:
  struct Received {
    probe::Probe probe;
    Endpoint from;
    std::size_t local;
  };
  // Waits until `until` for one authenticated probe from an allowed address on any socket.
  // Answers requests right away, from the socket they arrived on. nullopt on timeout.
  std::optional<Received> receive_until(Clock::time_point until);
  void send(std::size_t local, probe::Kind kind, const probe::TransactionId& tid,
            const Endpoint& to);
  bool allowed(const Endpoint& from) const;

  std::vector<stun::UdpSocket*> socks_;  // [0] is the main socket, the rest birthday sockets
  Endpoint birthday_target_;
  probe::Key key_;
  std::vector<Candidate> remote_;
  int sent_ = 0;
};

}  // namespace agent
