// stun_server: Binding-only STUN server with CHANGE-REQUEST support.
//
//   stun_server --ip 203.0.113.10 [--alt-ip 203.0.113.11] [--port 3478] [--alt-port 3479] [-v]
//
// Listens on every (ip, port) combination. A response normally leaves from the socket the request
// arrived on; CHANGE-REQUEST makes it leave from the other IP and/or the other port instead, which
// lets the client see whether its NAT lets in packets from an address it has not sent to.
// Without --alt-ip, requests that ask for a change of IP are ignored (no reply).
#include <poll.h>

#include <cstdio>
#include <cstdlib>
#include <exception>
#include <string_view>
#include <vector>

#include "stun/server.hpp"
#include "stun/udp.hpp"

namespace {

[[noreturn]] void usage() {
  std::fputs("usage: stun_server --ip A.B.C.D [--alt-ip A.B.C.D] [--port N] [--alt-port N] [-v]\n",
             stderr);
  std::exit(2);
}

struct Listener {
  stun::UdpSocket sock;
  int ip_index, port_index;  // 0 = primary, 1 = alternate
};

}  // namespace

int main(int argc, char** argv) try {
  std::optional<std::array<std::uint8_t, 4>> ip, alt_ip;
  std::uint16_t port = 3478, alt_port = 3479;
  bool verbose = false;
  for (int i = 1; i < argc; ++i) {
    std::string_view a = argv[i];
    auto value = [&] {
      if (i + 1 >= argc) usage();
      return std::string_view(argv[++i]);
    };
    if (a == "--ip") ip = stun::parse_ipv4(value());
    else if (a == "--alt-ip") { alt_ip = stun::parse_ipv4(value()); if (!alt_ip) usage(); }
    else if (a == "--port") port = static_cast<std::uint16_t>(std::atoi(value().data()));
    else if (a == "--alt-port") alt_port = static_cast<std::uint16_t>(std::atoi(value().data()));
    else if (a == "-v") verbose = true;
    else usage();
  }
  if (!ip || port == 0 || alt_port == 0 || port == alt_port) usage();

  std::vector<Listener> listeners;
  for (int ii = 0; ii < (alt_ip ? 2 : 1); ++ii)
    for (int pi = 0; pi < 2; ++pi)
      listeners.push_back({stun::UdpSocket({ii == 0 ? *ip : *alt_ip, pi == 0 ? port : alt_port}),
                           ii, pi});
  auto find = [&](int ii, int pi) -> Listener* {
    for (auto& l : listeners)
      if (l.ip_index == ii && l.port_index == pi) return &l;
    return nullptr;
  };

  std::vector<pollfd> fds;
  for (auto& l : listeners) {
    fds.push_back({l.sock.fd(), POLLIN, 0});
    std::fprintf(stderr, "stun_server: listening on %s\n",
                 stun::to_string(l.sock.local_endpoint()).c_str());
  }

  for (;;) {
    if (poll(fds.data(), fds.size(), -1) < 0) throw std::runtime_error("poll failed");
    for (std::size_t k = 0; k < fds.size(); ++k) {
      if (!(fds[k].revents & POLLIN)) continue;
      auto& in = listeners[k];
      auto d = in.sock.receive(std::chrono::milliseconds(0));
      if (!d) continue;
      auto reply = stun::handle_request(d->bytes, d->from);
      if (!reply) continue;
      // "Change" is relative to where the request arrived (XOR flips primary <-> alternate).
      Listener* out = find(in.ip_index ^ int{reply->change_ip}, in.port_index ^ int{reply->change_port});
      if (verbose)
        std::fprintf(stderr, "%s -> %s%s%s\n", stun::to_string(d->from).c_str(),
                     stun::to_string(in.sock.local_endpoint()).c_str(),
                     reply->change_ip ? " change-ip" : "", reply->change_port ? " change-port" : "");
      if (!out) continue;  // asked for a change of IP but we only have one
      out->sock.send_to(stun::encode(reply->response), d->from);
    }
  }
} catch (const std::exception& e) {
  std::fprintf(stderr, "stun_server: %s\n", e.what());
  return 1;
}
