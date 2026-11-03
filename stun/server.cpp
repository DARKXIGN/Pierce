#include "stun/server.hpp"

namespace stun {

std::optional<ServerReply> handle_request(std::span<const std::uint8_t> bytes,
                                          const Endpoint& from) {
  const auto req = decode(bytes);
  if (!req || req->type != kBindingRequest) return std::nullopt;
  ServerReply r;
  r.response.type = kBindingResponse;
  r.response.tid = req->tid;  // the client matches the response to its request by this ID
  r.response.xor_mapped = from;
  r.change_ip = (req->change_request & kChangeIp) != 0;
  r.change_port = (req->change_request & kChangePort) != 0;
  return r;
}

}  // namespace stun
