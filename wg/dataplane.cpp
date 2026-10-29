#include "wg/dataplane.hpp"

#include <poll.h>

#include <array>

namespace wg {

using Clock = std::chrono::steady_clock;

void DataPlane::send(std::span<const std::uint8_t> datagram) {
  try {
    sock_.send_to(datagram, peer_);
  } catch (const std::system_error&) {
    ++stats_.dropped;  // e.g. a transient "network unreachable"; WireGuard retransmits
  }
}

void DataPlane::from_network(const stun::Datagram& d) {
  if (d.from.ipv4 != peer_.ipv4) {
    ++stats_.dropped;
    return;
  }
  if (looks_like_wireguard(d.bytes)) {
    auto out = tunnel_.decapsulate(d.bytes);
    if (out.op == Tunnel::Op::ToTunnel) {
      tun_.write(out.data);
      ++stats_.from_peer;
    } else if (out.op == Tunnel::Op::ToNetwork) {
      // A handshake message to answer; then whatever BoringTun queued meanwhile.
      send(out.data);
      for (out = tunnel_.flush(); out.op == Tunnel::Op::ToNetwork; out = tunnel_.flush())
        send(out.data);
    } else if (out.op == Tunnel::Op::Error) {
      ++stats_.dropped;
    }
    return;
  }
  if (probe::looks_like_probe(d.bytes)) {
    // The peer may still be finishing its connectivity checks: keep answering them.
    if (auto p = probe::decode(d.bytes, key_); p && p->kind == probe::Kind::Request) {
      const auto resp = probe::encode({probe::Kind::Response, p->tid}, key_);
      send(resp);
    }
    return;
  }
  ++stats_.dropped;
}

DataPlaneStats DataPlane::run(Clock::time_point until) {
  constexpr auto kTick = std::chrono::milliseconds(100);
  std::array<std::uint8_t, 65536> buf;
  if (auto out = tunnel_.force_handshake(); out.op == Tunnel::Op::ToNetwork) send(out.data);
  auto next_tick = Clock::now() + kTick;

  std::array<pollfd, 2> fds{{{tun_.fd(), POLLIN, 0}, {sock_.fd(), POLLIN, 0}}};
  for (auto now = Clock::now(); now < until; now = Clock::now()) {
    const auto wait = std::chrono::ceil<std::chrono::milliseconds>(std::min(next_tick, until) - now);
    for (auto& f : fds) f.revents = 0;
    poll(fds.data(), fds.size(), static_cast<int>(std::max<long>(0, wait.count())));

    if (fds[0].revents & POLLIN) {
      // Drain the TUN device: every IP packet routed to it goes to the peer, encrypted.
      while (auto n = tun_.read(buf)) {
        auto out = tunnel_.encapsulate(std::span(buf.data(), *n));
        if (out.op == Tunnel::Op::ToNetwork) {
          send(out.data);
          ++stats_.to_peer;
        }
      }
    }
    if (fds[1].revents & POLLIN) {
      while (auto d = sock_.receive(std::chrono::milliseconds(0))) from_network(*d);
    }
    if (Clock::now() >= next_tick) {
      // Timers: handshake retransmits, rekeying, persistent keepalive.
      if (auto out = tunnel_.tick(); out.op == Tunnel::Op::ToNetwork) send(out.data);
      next_tick += kTick;
    }
  }
  return stats_;
}

}  // namespace wg
