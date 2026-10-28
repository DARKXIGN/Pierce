#pragma once
#include <chrono>
#include <optional>

#include "stun/message.hpp"
#include "stun/udp.hpp"

namespace stun {

// Sends a Binding Request from `sock` to `to` and waits for the matching response, retransmitting
// up to `tries` times with `timeout` per try. `change` is an optional CHANGE-REQUEST (kChangeIp /
// kChangePort). Datagrams that are not the matching response are ignored.
std::optional<Message> binding(UdpSocket& sock, const Endpoint& to, std::uint8_t change,
                               std::chrono::milliseconds timeout, int tries);

}  // namespace stun
