#pragma once
#include <optional>
#include <span>

#include "stun/message.hpp"

namespace stun {

struct ServerReply {
  Message response;
  // Send the response from the server's other IP / other port (CHANGE-REQUEST, RFC 5780).
  bool change_ip = false;
  bool change_port = false;
};

// Answers a Binding Request with the sender's address as seen by the server (XOR-MAPPED-ADDRESS).
// Anything else, including garbage, gets no reply.
std::optional<ServerReply> handle_request(std::span<const std::uint8_t> bytes,
                                          const Endpoint& from);

}  // namespace stun
