#pragma once
#include <chrono>
#include <cstdint>
#include <map>
#include <vector>

#include "relay/protocol.hpp"
#include "stun/udp.hpp"

// The agent's side of the relay protocol (relay/protocol.hpp).
namespace agent {

// RTT to each relay in microseconds, by index into `relays`. Pings all of them at once from
// `sock` and waits up to `timeout`; relays that do not answer are left out.
std::map<std::uint32_t, std::uint32_t> measure_relays(stun::UdpSocket& sock,
                                                       const std::vector<stun::Endpoint>& relays,
                                                       std::chrono::milliseconds timeout);

// Sends BIND with `token` from `sock` until the relay answers BOUND. False if it never does.
bool bind_relay(stun::UdpSocket& sock, const stun::Endpoint& relay, const relay::TokenBytes& token,
                std::chrono::milliseconds timeout, int tries);

}  // namespace agent
