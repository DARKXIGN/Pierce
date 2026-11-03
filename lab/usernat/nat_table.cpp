#include "lab/usernat/nat_table.hpp"

namespace usernat {

Table::Table(std::uint16_t port_min, std::uint16_t port_max, std::uint16_t step,
             std::chrono::seconds lifetime)
    : port_min_(port_min), port_max_(port_max), step_(step), lifetime_(lifetime), next_(port_min) {}

std::uint16_t Table::advance(std::uint16_t port) const {
  // Wrap around inside [port_min, port_max]. Done in 32 bits so port + step cannot overflow.
  const std::uint32_t span = std::uint32_t{port_max_} - port_min_ + 1;
  return static_cast<std::uint16_t>(port_min_ + (std::uint32_t{port} - port_min_ + step_) % span);
}

std::optional<std::uint16_t> Table::outbound(Endpoint inner, Endpoint remote,
                                             Clock::time_point now) {
  if (auto it = by_flow_.find({inner, remote}); it != by_flow_.end()) {
    by_port_.at(it->second).last_used = now;
    return it->second;
  }
  // New destination: take the next port in sequence, skipping ports that are still mapped.
  const std::uint32_t span = std::uint32_t{port_max_} - port_min_ + 1;
  std::uint16_t port = next_;
  for (std::uint32_t tries = 0; tries < span; ++tries, port = advance(port)) {
    if (by_port_.contains(port)) continue;
    by_port_[port] = Mapping{inner, remote, now};
    by_flow_[{inner, remote}] = port;
    next_ = advance(port);
    return port;
  }
  return std::nullopt;
}

std::optional<Endpoint> Table::inbound(std::uint16_t public_port, Endpoint remote,
                                       Clock::time_point now) {
  auto it = by_port_.find(public_port);
  if (it == by_port_.end() || it->second.remote != remote) return std::nullopt;
  it->second.last_used = now;
  return it->second.inner;
}

std::size_t Table::expire(Clock::time_point now) {
  std::size_t removed = 0;
  for (auto it = by_port_.begin(); it != by_port_.end();) {
    if (now - it->second.last_used > lifetime_) {
      by_flow_.erase({it->second.inner, it->second.remote});
      it = by_port_.erase(it);
      ++removed;
    } else {
      ++it;
    }
  }
  return removed;
}

}  // namespace usernat
