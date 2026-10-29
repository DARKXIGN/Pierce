// nat_detect: classify the NAT in front of this host.
//
//   nat_detect --server 192.0.32.10:3478 --alt-ip 192.0.32.11 [--alt-port 3479]
//              [--timeout-ms 200] [--tries 3] [--repeat N]
//
// Prints one line per run: "<type>,<milliseconds>", e.g. "symmetric-sequential,3".
// Exit code 0 if every run got a type, 1 if any run got no response from the server.
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <string_view>

#include "stun/detector.hpp"

namespace {
[[noreturn]] void usage() {
  std::fputs(
      "usage: nat_detect --server IP:PORT --alt-ip IP [--alt-port N] [--timeout-ms N] [--tries N]\n"
      "                  [--repeat N]\n",
      stderr);
  std::exit(2);
}
}  // namespace

int main(int argc, char** argv) try {
  stun::DetectorConfig cfg;
  bool have_server = false, have_alt_ip = false;
  int repeat = 1;
  for (int i = 1; i < argc; ++i) {
    std::string_view a = argv[i];
    auto value = [&] {
      if (i + 1 >= argc) usage();
      return std::string_view(argv[++i]);
    };
    if (a == "--server") {
      auto ep = stun::parse_endpoint(value());
      if (!ep) usage();
      cfg.server = *ep;
      have_server = true;
    } else if (a == "--alt-ip") {
      auto ip = stun::parse_ipv4(value());
      if (!ip) usage();
      cfg.alt_ip = *ip;
      have_alt_ip = true;
    } else if (a == "--alt-port") cfg.alt_port = static_cast<std::uint16_t>(std::atoi(value().data()));
    else if (a == "--timeout-ms") cfg.timeout = std::chrono::milliseconds(std::atoi(value().data()));
    else if (a == "--tries") cfg.tries = std::atoi(value().data());
    else if (a == "--repeat") repeat = std::atoi(value().data());
    else usage();
  }
  if (!have_server || !have_alt_ip || cfg.alt_port == 0 || cfg.timeout.count() <= 0 ||
      cfg.tries <= 0 || repeat <= 0)
    usage();

  stun::Detector detector(cfg);
  int rc = 0;
  for (int i = 0; i < repeat; ++i) {
    const auto start = std::chrono::steady_clock::now();
    const auto type = detector.detect();
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - start).count();
    std::printf("%s,%lld\n", std::string(stun::to_string(type)).c_str(), static_cast<long long>(ms));
    std::fflush(stdout);
    if (type == stun::NatType::Unknown) rc = 1;
  }
  return rc;
} catch (const std::exception& e) {
  std::fprintf(stderr, "nat_detect: %s\n", e.what());
  return 1;
}
