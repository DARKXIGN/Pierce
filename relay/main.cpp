// pierce-relay: UDP relay for peers that cannot connect directly.
//
//   pierce-relay --listen 203.0.113.10:3480 --secret HEX [--idle 120] [-v]
//
// --secret is shared with the coordination server, which issues the tokens (relay/protocol.hpp).
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <string>
#include <string_view>

#include "relay/table.hpp"
#include "stun/udp.hpp"

namespace {
[[noreturn]] void usage() {
  std::fputs("usage: pierce-relay --listen IP:PORT --secret HEX [--idle SEC] [-v]\n", stderr);
  std::exit(2);
}

std::uint64_t unix_now() { return static_cast<std::uint64_t>(std::time(nullptr)); }
}  // namespace

int main(int argc, char** argv) try {
  std::optional<stun::Endpoint> listen;
  std::optional<relay::Secret> secret;
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
    else if (a == "--idle") idle = std::atoi(std::string(value()).c_str());
    else if (a == "-v") verbose = true;
    else usage();
  }
  if (!listen || !secret || idle <= 0) usage();

  stun::UdpSocket sock(*listen);
  relay::Table table(*secret, std::chrono::seconds(idle));
  std::fprintf(stderr, "pierce-relay: listening on %s\n", stun::to_string(*listen).c_str());
  auto last_expire = unix_now();
  for (;;) {
    auto d = sock.receive(std::chrono::milliseconds(1000));
    const auto now = unix_now();
    if (now != last_expire) {
      table.expire(now);
      last_expire = now;
    }
    if (!d) continue;
    if (auto out = table.handle(d->bytes, d->from, now)) {
      if (verbose && relay::control_type(d->bytes) == relay::Type::Bind)
        std::fprintf(stderr, "bind %s (%zu sessions)\n", stun::to_string(d->from).c_str(),
                     table.sessions());
      try {
        sock.send_to(out->bytes, out->to);
      } catch (const std::system_error& e) {
        std::fprintf(stderr, "send to %s: %s\n", stun::to_string(out->to).c_str(), e.what());
      }
    }
  }
} catch (const std::exception& e) {
  std::fprintf(stderr, "pierce-relay: %s\n", e.what());
  return 1;
}
