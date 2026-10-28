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
  std::chrono::milliseconds interval{20};   // one probe request per interval, round robin
  std::chrono::milliseconds timeout{3000};  // give up on the direct path after this
  // After we are connected, keep answering the peer's requests until it has been quiet this long,
  // so the peer can finish too.
  std::chrono::milliseconds linger{300};
};

struct PunchResult {
  bool success = false;
  Clock::time_point connected_at{};
  std::optional<Endpoint> path;  // the remote address that answered our probe
};

struct HoldStats {
  int sent = 0;
  int answered = 0;
};

class Puncher {
 public:
  // `remote` comes from signaling. Probes are only ever sent to IPs in that list.
  Puncher(stun::UdpSocket& sock, probe::Key key, std::vector<Candidate> remote);

  PunchResult connect(const PunchOptions& opt);

  // Keepalive on an established path: one request per `interval` for `duration`, answering the
  // peer's requests in between. Needs no coordination server.
  HoldStats hold(const Endpoint& path, std::chrono::milliseconds duration,
                 std::chrono::milliseconds interval);

  int probes_sent() const { return sent_; }
  const std::vector<Candidate>& remote() const { return remote_; }

 private:
  struct Received {
    probe::Probe probe;
    Endpoint from;
  };
  // Waits until `until` for one authenticated probe from an allowed address. Answers requests
  // right away. nullopt on timeout.
  std::optional<Received> receive_until(Clock::time_point until);
  void send(probe::Kind kind, const probe::TransactionId& tid, const Endpoint& to);
  bool allowed(const Endpoint& from) const;

  stun::UdpSocket& sock_;
  probe::Key key_;
  std::vector<Candidate> remote_;
  int sent_ = 0;
};

}  // namespace agent
