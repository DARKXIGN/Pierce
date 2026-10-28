#include "agent/punch.hpp"

#include <poll.h>

#include <algorithm>
#include <map>

namespace agent {

Puncher::Puncher(stun::UdpSocket& main, probe::Key key, std::vector<Candidate> remote)
    : socks_{&main}, key_(std::move(key)), remote_(std::move(remote)) {
  sort_and_dedupe(remote_);
}

void Puncher::add_birthday_sockets(std::vector<stun::UdpSocket>& extra, const Endpoint& target) {
  birthday_target_ = target;
  for (auto& s : extra) socks_.push_back(&s);
}

bool Puncher::allowed(const Endpoint& from) const {
  // Same IP as some signaled candidate. The port may differ: a symmetric NAT on the peer's side
  // gives its probes to us a new port, and we must be able to answer that.
  return std::any_of(remote_.begin(), remote_.end(),
                     [&](const Candidate& c) { return c.ep.ipv4 == from.ipv4; });
}

void Puncher::send(std::size_t local, probe::Kind kind, const probe::TransactionId& tid,
                   const Endpoint& to) {
  const auto bytes = probe::encode({kind, tid}, key_);
  try {
    socks_[local]->send_to(bytes, to);
  } catch (const std::system_error&) {
    // e.g. "network unreachable" for a host candidate on another LAN; that pair just fails.
  }
  ++sent_;
}

std::optional<Puncher::Received> Puncher::receive_until(Clock::time_point until) {
  std::vector<pollfd> fds;
  for (auto* s : socks_) fds.push_back({s->fd(), POLLIN, 0});
  for (auto now = Clock::now(); now < until; now = Clock::now()) {
    const auto wait = std::chrono::ceil<std::chrono::milliseconds>(until - now);
    for (auto& f : fds) f.revents = 0;
    if (poll(fds.data(), fds.size(), static_cast<int>(wait.count())) <= 0) return std::nullopt;
    for (std::size_t i = 0; i < fds.size(); ++i) {
      if (!(fds[i].revents & POLLIN)) continue;
      auto d = socks_[i]->receive(std::chrono::milliseconds(0));
      if (!d || !probe::looks_like_probe(d->bytes) || !allowed(d->from)) continue;
      auto p = probe::decode(d->bytes, key_);
      if (!p) continue;  // wrong key or forged: drop silently
      if (p->kind == probe::Kind::Request) send(i, probe::Kind::Response, p->tid, d->from);
      return Received{*p, d->from, i};
    }
  }
  return std::nullopt;
}

PunchResult Puncher::connect(const PunchOptions& opt) {
  PunchResult result;
  const auto start = Clock::now();
  const auto deadline = start + opt.timeout;
  struct Sent {
    std::size_t local;
    Endpoint to;
  };
  std::map<probe::TransactionId, Sent> pending;  // our requests, by transaction ID
  std::size_t next = 0;
  auto next_send = start;
  auto last_request_from_peer = start;

  auto send_request = [&](std::size_t local, const Endpoint& to) {
    const auto tid = probe::random_tid();
    pending[tid] = {local, to};
    send(local, probe::Kind::Request, tid, to);
  };
  // The round robin runs over the main socket's candidates, then over the birthday sockets
  // (each of which only ever probes the birthday target).
  auto pairs = [&] { return remote_.size() + (socks_.size() - 1); };
  auto interval = [&] {
    const auto per_pair = opt.pass / std::max<std::size_t>(pairs(), 1);
    return std::clamp(std::chrono::duration_cast<std::chrono::milliseconds>(per_pair),
                      std::chrono::milliseconds(1), opt.interval);
  };

  for (;;) {
    const auto now = Clock::now();
    if (result.success) {
      // Connected: stop sending, but keep answering until the peer has gone quiet.
      const auto quiet_since = std::max(result.connected_at, last_request_from_peer);
      if (now - quiet_since >= opt.linger) break;
    } else if (now >= deadline) {
      break;
    } else if (now >= next_send && pairs() > 0) {
      const std::size_t i = next++ % pairs();
      if (i < remote_.size()) send_request(0, remote_[i].ep);
      else send_request(i - remote_.size() + 1, birthday_target_);
      next_send = now + interval();
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
        send_request(r->local, r->from);
      }
    } else if (auto it = pending.find(r->probe.tid); it != pending.end() && !result.success) {
      result.success = true;
      result.connected_at = Clock::now();
      result.path = it->second.to;
      result.local = it->second.local;
    }
  }
  return result;
}

HoldStats Puncher::hold(std::size_t local, const Endpoint& path,
                        std::chrono::milliseconds duration, std::chrono::milliseconds interval) {
  HoldStats stats;
  const auto end = Clock::now() + duration;
  probe::TransactionId outstanding{};
  bool waiting = false;
  for (auto next_send = Clock::now(); Clock::now() < end;) {
    if (Clock::now() >= next_send) {
      outstanding = probe::random_tid();
      waiting = true;
      send(local, probe::Kind::Request, outstanding, path);
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
