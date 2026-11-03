#include "stun/client.hpp"

namespace stun {

std::optional<Message> binding(UdpSocket& sock, const Endpoint& to, std::uint8_t change,
                               std::chrono::milliseconds timeout, int tries) {
  Message req;
  req.type = kBindingRequest;
  req.tid = random_tid();
  req.change_request = change;
  const auto bytes = encode(req);
  for (int i = 0; i < tries; ++i) {
    sock.send_to(bytes, to);
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    for (auto now = std::chrono::steady_clock::now(); now < deadline;
         now = std::chrono::steady_clock::now()) {
      auto d = sock.receive(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now));
      if (!d) break;
      // Ignore stray datagrams, e.g. a late response to an earlier request.
      auto m = decode(d->bytes);
      if (m && m->type == kBindingResponse && m->tid == req.tid && m->xor_mapped) return m;
    }
  }
  return std::nullopt;
}

}  // namespace stun
