#include "agent/relay_client.hpp"

#include <openssl/rand.h>

namespace agent {

using Clock = std::chrono::steady_clock;

std::map<std::uint32_t, std::uint32_t> measure_relays(stun::UdpSocket& sock,
                                                       const std::vector<stun::Endpoint>& relays,
                                                       std::chrono::milliseconds timeout) {
  std::map<std::uint32_t, std::uint32_t> rtt;
  std::map<std::uint64_t, std::uint32_t> by_nonce;  // nonce -> relay index
  const auto sent = Clock::now();
  for (std::uint32_t i = 0; i < relays.size(); ++i) {
    std::uint64_t nonce = 0;
    RAND_bytes(reinterpret_cast<unsigned char*>(&nonce), sizeof nonce);
    by_nonce[nonce] = i;
    try {
      sock.send_to(relay::ping_message(nonce), relays[i]);
    } catch (const std::system_error&) {
    }
  }
  const auto deadline = sent + timeout;
  while (rtt.size() < relays.size()) {
    const auto now = Clock::now();
    if (now >= deadline) break;
    auto d = sock.receive(std::chrono::ceil<std::chrono::milliseconds>(deadline - now));
    if (!d) break;
    if (relay::control_type(d->bytes) != relay::Type::Pong) continue;
    auto n = relay::nonce_of(d->bytes);
    auto it = n ? by_nonce.find(*n) : by_nonce.end();
    if (it == by_nonce.end() || d->from != relays[it->second]) continue;
    const auto us = std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - sent);
    rtt[it->second] = static_cast<std::uint32_t>(us.count());
  }
  return rtt;
}

bool bind_relay(stun::UdpSocket& sock, const stun::Endpoint& relay, const relay::TokenBytes& token,
                std::chrono::milliseconds timeout, int tries) {
  const auto msg = relay::bind_message(token);
  for (int i = 0; i < tries; ++i) {
    try {
      sock.send_to(msg, relay);
    } catch (const std::system_error&) {
      return false;
    }
    const auto deadline = Clock::now() + timeout;
    for (auto now = Clock::now(); now < deadline; now = Clock::now()) {
      auto d = sock.receive(std::chrono::ceil<std::chrono::milliseconds>(deadline - now));
      if (!d) break;
      if (d->from == relay && relay::control_type(d->bytes) == relay::Type::Bound) return true;
    }
  }
  return false;
}

}  // namespace agent
