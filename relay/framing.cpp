#include "relay/framing.hpp"

namespace relay {

std::vector<std::uint8_t> frame(std::span<const std::uint8_t> d) {
  std::vector<std::uint8_t> out;
  out.reserve(d.size() + 2);
  out.push_back(static_cast<std::uint8_t>(d.size() >> 8));
  out.push_back(static_cast<std::uint8_t>(d.size()));
  out.insert(out.end(), d.begin(), d.end());
  return out;
}

std::optional<std::vector<std::uint8_t>> Deframer::next() {
  if (buf_.size() < 2) return std::nullopt;
  const std::size_t len = (std::size_t{buf_[0]} << 8) | buf_[1];
  if (buf_.size() < 2 + len) return std::nullopt;
  std::vector<std::uint8_t> out(buf_.begin() + 2, buf_.begin() + 2 + static_cast<long>(len));
  buf_.erase(buf_.begin(), buf_.begin() + 2 + static_cast<long>(len));
  return out;
}

stun::Endpoint stream_endpoint(std::uint32_t id) {
  return {{0, static_cast<std::uint8_t>(id >> 16), static_cast<std::uint8_t>(id >> 8),
           static_cast<std::uint8_t>(id)},
          0};
}

std::optional<std::uint32_t> stream_id(const stun::Endpoint& ep) {
  if (ep.ipv4[0] != 0 || ep.port != 0) return std::nullopt;
  return (std::uint32_t{ep.ipv4[1]} << 16) | (std::uint32_t{ep.ipv4[2]} << 8) | ep.ipv4[3];
}

}  // namespace relay
