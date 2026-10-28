#include "relay/table.hpp"

#include <algorithm>

namespace relay {

std::optional<Outgoing> Table::handle(std::span<const std::uint8_t> bytes, const Endpoint& from,
                                      std::uint64_t now) {
  const auto type = control_type(bytes);
  if (type == Type::Ping) {
    if (auto n = nonce_of(bytes)) {
      auto pong = ping_message(*n);
      pong[1] = static_cast<std::uint8_t>(Type::Pong);
      return Outgoing{pong, from};
    }
    return std::nullopt;
  }
  if (type == Type::Bind) {
    auto token = verify_token(bytes.subspan(2), secret_, now);
    if (!token) return std::nullopt;  // forged or expired: silence
    auto& s = sessions_[token->session];
    s.expires = token->expires;
    auto it = std::find_if(s.slots.begin(), s.slots.end(), [&](const Slot& x) { return x.ep == from; });
    if (it != s.slots.end()) {
      it->last_seen = now;
    } else {
      if (s.slots.size() == 2) {
        // A third endpoint with a valid token: one peer's NAT gave it a new port. Replace the
        // slot that has been quiet longest.
        auto old = std::min_element(s.slots.begin(), s.slots.end(), [](const Slot& a, const Slot& b) {
          return a.last_seen < b.last_seen;
        });
        by_endpoint_.erase(old->ep);
        *old = {from, now};
      } else {
        s.slots.push_back({from, now});
      }
      // An endpoint belongs to one session at a time.
      if (auto prev = by_endpoint_.find(from); prev != by_endpoint_.end() && prev->second != token->session) {
        auto& ps = sessions_[prev->second].slots;
        ps.erase(std::remove_if(ps.begin(), ps.end(), [&](const Slot& x) { return x.ep == from; }), ps.end());
      }
      by_endpoint_[from] = token->session;
    }
    return Outgoing{bound_message(), from};
  }
  if (type) return std::nullopt;  // BOUND / PONG sent to the relay: ignore

  // Data: forward from a bound endpoint to the other one in its session.
  auto e = by_endpoint_.find(from);
  if (e == by_endpoint_.end()) return std::nullopt;
  auto& s = sessions_.at(e->second);
  for (auto& slot : s.slots) {
    if (slot.ep == from) slot.last_seen = now;
  }
  for (const auto& slot : s.slots) {
    if (slot.ep != from) return Outgoing{{bytes.begin(), bytes.end()}, slot.ep};
  }
  return std::nullopt;  // the other peer has not bound yet
}

void Table::expire(std::uint64_t now) {
  for (auto it = sessions_.begin(); it != sessions_.end();) {
    auto& s = it->second;
    s.slots.erase(std::remove_if(s.slots.begin(), s.slots.end(),
                                 [&](const Slot& x) {
                                   const bool idle = now - x.last_seen > std::uint64_t(idle_.count());
                                   if (idle || s.expires <= now) by_endpoint_.erase(x.ep);
                                   return idle || s.expires <= now;
                                 }),
                  s.slots.end());
    if (s.slots.empty()) it = sessions_.erase(it);
    else ++it;
  }
}

}  // namespace relay
