// pierce-relay: UDP relay for peers that cannot connect directly.
//
//   pierce-relay --listen 192.0.32.10:3480 --secret HEX [--idle 120] [-v]
//                [--tls-listen 192.0.32.10:3443 --tls-cert cert.pem --tls-key key.pem]
//
// With --tls-listen it also accepts agents over TCP/TLS (for networks that block UDP); they speak
// the same protocol, one datagram per length-prefixed frame (relay/framing.hpp).
//
// --secret is shared with the coordination server, which issues the tokens (relay/protocol.hpp).
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <string>
#include <string_view>

#include <poll.h>

#include "relay/table.hpp"
#include "relay/tls_server.hpp"
#include "stun/udp.hpp"

namespace {
[[noreturn]] void usage() {
  std::fputs("usage: pierce-relay --listen IP:PORT --secret HEX [--idle SEC] [-v]\n"
             "                    [--tls-listen IP:PORT --tls-cert PEM --tls-key PEM]\n", stderr);
  std::exit(2);
}

std::uint64_t unix_now() { return static_cast<std::uint64_t>(std::time(nullptr)); }
}  // namespace

int main(int argc, char** argv) try {
  std::optional<stun::Endpoint> listen, tls_listen;
  std::optional<relay::Secret> secret;
  std::string tls_cert, tls_key;
  int idle = 120;
  bool verbose = false;
  for (int i = 1; i < argc; ++i) {
    std::string_view a = argv[i];
    auto value = [&] {
      if (i + 1 >= argc) usage();
      return std::string_view(argv[++i]);
    };
    if (a == "--listen") listen = stun::parse_endpoint(value());
    else if (a == "--secret") secret = relay::secret_from_hex(value());
    else if (a == "--tls-listen") tls_listen = stun::parse_endpoint(value());
    else if (a == "--tls-cert") tls_cert = value();
    else if (a == "--tls-key") tls_key = value();
    else if (a == "--idle") idle = std::atoi(std::string(value()).c_str());
    else if (a == "-v") verbose = true;
    else usage();
  }
  if (!listen || !secret || idle <= 0) usage();
  if (tls_listen && (tls_cert.empty() || tls_key.empty())) usage();

  stun::UdpSocket sock(*listen);
  relay::Table table(*secret, std::chrono::seconds(idle));
  std::optional<relay::TlsServer> tls;
  if (tls_listen) tls.emplace(*tls_listen, tls_cert, tls_key);
  std::fprintf(stderr, "pierce-relay: listening on %s%s%s\n", stun::to_string(*listen).c_str(),
               tls_listen ? ", TLS on " : "", tls_listen ? stun::to_string(*tls_listen).c_str() : "");

  // One datagram in, from a UDP endpoint or a TLS connection (with its stand-in endpoint): look
  // it up in the table and send the result over whichever transport its destination uses.
  auto dispatch = [&](std::span<const std::uint8_t> bytes, const stun::Endpoint& from) {
    auto out = table.handle(bytes, from, unix_now());
    if (!out) return;
    if (verbose && relay::control_type(bytes) == relay::Type::Bind)
      std::fprintf(stderr, "bind %s (%zu sessions)\n", stun::to_string(from).c_str(), table.sessions());
    if (auto id = relay::stream_id(out->to)) {
      if (tls) tls->send(*id, out->bytes);
      return;
    }
    try {
      sock.send_to(out->bytes, out->to);
    } catch (const std::system_error& e) {
      std::fprintf(stderr, "send to %s: %s\n", stun::to_string(out->to).c_str(), e.what());
    }
  };

  auto last_expire = unix_now();
  std::vector<pollfd> fds;
  for (;;) {
    fds.assign({{sock.fd(), POLLIN, 0}});
    if (tls) tls->add_pollfds(fds);
    poll(fds.data(), fds.size(), 1000);
    if (const auto now = unix_now(); now != last_expire) {
      table.expire(now);
      last_expire = now;
    }
    if (fds[0].revents & POLLIN)
      while (auto d = sock.receive(std::chrono::milliseconds(0))) dispatch(d->bytes, d->from);
    if (tls)
      tls->service(fds, [&](std::uint32_t id, std::span<const std::uint8_t> bytes) {
        dispatch(bytes, relay::stream_endpoint(id));
      });
  }
} catch (const std::exception& e) {
  std::fprintf(stderr, "pierce-relay: %s\n", e.what());
  return 1;
}
