#include "agent/punch.hpp"

#include <algorithm>
#include <map>

namespace agent {

Puncher::Puncher(stun::UdpSocket& sock, probe::Key key, std::vector<Candidate> remote)
    : sock_(sock), key_(std::move(key)), remote_(std::move(remote)) {
  sort_and_dedupe(remote_);
}

bool Puncher::allowed(const Endpoint& from) const {
  // Same IP as some signaled candidate. The port may differ: a symmetric NAT on the peer's side
  // gives its probes to us a new port, and we must be able to answer that.
  return std::any_of(remote_.begin(), remote_.end(),
                     [&](const Candidate& c) { return c.ep.ipv4 == from.ipv4; });
}

void Puncher::send(probe::Kind kind, const probe::TransactionId& tid, const Endpoint& to) {
  const auto bytes = probe::encode({kind, tid}, key_);
  try {
    sock_.send_to(bytes, to);
  } catch (const std::system_error&) {
    // e.g. "network unreachable" for a host candidate on another LAN; that pair just fails.
  }
  ++sent_;
}

std::optional<Puncher::Received> Puncher::receive_until(Clock::time_point until) {
  for (auto now = Clock::now(); now < until; now = Clock::now()) {
    auto d = sock_.receive(std::chrono::ceil<std::chrono::milliseconds>(until - now));
    if (!d) return std::nullopt;
    if (!probe::looks_like_probe(d->bytes) || !allowed(d->from)) continue;
    auto p = probe::decode(d->bytes, key_);
    if (!p) continue;  // wrong key or forged: drop silently
    if (p->kind == probe::Kind::Request) send(probe::Kind::Response, p->tid, d->from);
    return Received{*p, d->from};
  }
  return std::nullopt;
}

PunchResult Puncher::connect(const PunchOptions& opt) {
  PunchResult result;
  const auto start = Clock::now();
  const auto deadline = start + opt.timeout;
  std::map<probe::TransactionId, Endpoint> pending;  // our requests, by transaction ID
  std::size_t next = 0;
  auto next_send = start;
  auto last_request_from_peer = start;

  auto send_request = [&](const Endpoint& to) {
    const auto tid = probe::random_tid();
    pending[tid] = to;
    send(probe::Kind::Request, tid, to);
  };

  for (;;) {
    const auto now = Clock::now();
    if (result.success) {
      // Connected: stop sending, but keep answering until the peer has gone quiet.
      const auto quiet_since = std::max(result.connected_at, last_request_from_peer);
      if (now - quiet_since >= opt.linger) break;
    } else if (now >= deadline) {
      break;
    } else if (now >= next_send && !remote_.empty()) {
      // Round robin over the candidates, highest priority first.
      send_request(remote_[next++ % remote_.size()].ep);
      next_send = now + opt.interval;
    }

    const auto wait_until = result.success ? now + opt.linger
                                           : std::min(deadline, std::max(next_send, now));
    auto r = receive_until(wait_until);
    if (!r) continue;

    if (r->probe.kind == probe::Kind::Request) {
      last_request_from_peer = Clock::now();
      // A request got through to us, so the path back to its source is likely open: probe it
      // right away (a "triggered check", RFC 8445 §7.3.1.4) instead of waiting for our round
      // robin to come back to it, which with many candidates can take longer than the peer
      // stays around after it has connected.
      // A source we do not know yet is a peer-reflexive candidate. That is how we reach a peer
      // behind a symmetric NAT, whose probes come from a port it never told anyone about.
      const bool known = std::any_of(remote_.begin(), remote_.end(),
                                     [&](const Candidate& c) { return c.ep == r->from; });
      if (!result.success) {
        if (!known) {
          remote_.insert(remote_.begin(), {CandidateType::PeerReflexive, r->from,
                                           priority(CandidateType::PeerReflexive)});
          next = 0;
        }
        send_request(r->from);
      }
    } else if (auto it = pending.find(r->probe.tid); it != pending.end() && !result.success) {
      result.success = true;
      result.connected_at = Clock::now();
      result.path = it->second;
    }
  }
  return result;
}

HoldStats Puncher::hold(const Endpoint& path, std::chrono::milliseconds duration,
                        std::chrono::milliseconds interval) {
  HoldStats stats;
  const auto end = Clock::now() + duration;
  probe::TransactionId outstanding{};
  bool waiting = false;
  for (auto next_send = Clock::now(); Clock::now() < end;) {
    if (Clock::now() >= next_send) {
      outstanding = probe::random_tid();
      waiting = true;
      send(probe::Kind::Request, outstanding, path);
      ++stats.sent;
      next_send += interval;
    }
    auto r = receive_until(std::min(next_send, end));
    if (r && waiting && r->probe.kind == probe::Kind::Response && r->probe.tid == outstanding) {
      ++stats.answered;
      waiting = false;
    }
  }
  return stats;
}

}  // namespace agent
