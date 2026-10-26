// usernat: the symmetric-sequential NAT for the lab. Runs inside a NAT router namespace.
//
//   usernat --lan nA-lan --wan nA-wan --public-ip 203.0.113.1 [--lifetime 120]
//           [--port-min 20000] [--port-max 60999] [--step 1] [-v]
//
// How it moves packets (setup.sh sets up the nftables side):
//   - The kernel does not forward or track UDP in this namespace; nftables drops it. ICMP and the
//     rest still go through the kernel's masquerade, so ping keeps working.
//   - We read UDP packets with AF_PACKET sockets on both interfaces. A packet socket sees each
//     packet before netfilter drops it, so we get a copy of everything.
//   - We rewrite the addresses and send the result with a raw IP socket, which lets us choose any
//     source address (the remote peer's IP when delivering to the LAN host).
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>

#include "lab/usernat/nat_table.hpp"
#include "lab/usernat/packet.hpp"

namespace {

using usernat::Endpoint;

struct Options {
  std::string lan, wan;
  std::uint32_t public_ip = 0;
  int lifetime_s = 120;
  std::uint16_t port_min = 20000, port_max = 60999, step = 1;
  bool verbose = false;
};

[[noreturn]] void die(const char* what) {
  std::perror(what);
  std::exit(1);
}

[[noreturn]] void usage() {
  std::fputs(
      "usage: usernat --lan IF --wan IF --public-ip A.B.C.D [--lifetime SEC] [--port-min N]\n"
      "               [--port-max N] [--step N] [-v]\n",
      stderr);
  std::exit(2);
}

int to_int(std::string_view s) {
  int v = 0;
  auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
  if (ec != std::errc{} || p != s.data() + s.size()) usage();
  return v;
}

Options parse_args(int argc, char** argv) {
  Options o;
  for (int i = 1; i < argc; ++i) {
    std::string_view a = argv[i];
    auto value = [&]() -> std::string_view {
      if (i + 1 >= argc) usage();
      return argv[++i];
    };
    if (a == "--lan") o.lan = value();
    else if (a == "--wan") o.wan = value();
    else if (a == "--public-ip") {
      in_addr addr{};
      if (inet_pton(AF_INET, std::string(value()).c_str(), &addr) != 1) usage();
      o.public_ip = ntohl(addr.s_addr);
    } else if (a == "--lifetime") o.lifetime_s = to_int(value());
    else if (a == "--port-min") o.port_min = static_cast<std::uint16_t>(to_int(value()));
    else if (a == "--port-max") o.port_max = static_cast<std::uint16_t>(to_int(value()));
    else if (a == "--step") o.step = static_cast<std::uint16_t>(to_int(value()));
    else if (a == "-v") o.verbose = true;
    else usage();
  }
  if (o.lan.empty() || o.wan.empty() || o.public_ip == 0 || o.port_min == 0 ||
      o.port_min > o.port_max || o.step == 0 || o.lifetime_s <= 0)
    usage();
  return o;
}

// Packet socket bound to one interface, delivering IPv4 packets without the Ethernet header.
int open_packet_socket(const std::string& ifname) {
  int fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
  if (fd < 0) die("socket(AF_PACKET)");
  sockaddr_ll sll{};
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = htons(ETH_P_IP);
  sll.sll_ifindex = static_cast<int>(if_nametoindex(ifname.c_str()));
  if (sll.sll_ifindex == 0) die(ifname.c_str());
  if (bind(fd, reinterpret_cast<sockaddr*>(&sll), sizeof sll) < 0) die("bind(AF_PACKET)");
  return fd;
}

std::string str(Endpoint e) {
  char buf[32];
  std::snprintf(buf, sizeof buf, "%u.%u.%u.%u:%u", e.ip >> 24, (e.ip >> 16) & 0xFF,
                (e.ip >> 8) & 0xFF, e.ip & 0xFF, e.port);
  return buf;
}

}  // namespace

int main(int argc, char** argv) {
  const Options opt = parse_args(argc, argv);
  usernat::Table table(opt.port_min, opt.port_max, opt.step, std::chrono::seconds(opt.lifetime_s));

  const int lan_fd = open_packet_socket(opt.lan);
  const int wan_fd = open_packet_socket(opt.wan);
  // IPPROTO_RAW: we write the whole IP header ourselves; the kernel only routes the packet.
  const int raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (raw_fd < 0) die("socket(SOCK_RAW)");

  std::fprintf(stderr, "usernat: %s -> %s as %s, ports %u-%u step %u, lifetime %ds\n",
               opt.lan.c_str(), opt.wan.c_str(), str({opt.public_ip, 0}).c_str(), opt.port_min,
               opt.port_max, opt.step, opt.lifetime_s);

  auto send_raw = [&](std::span<const std::uint8_t> pkt, std::uint32_t dst_ip) {
    sockaddr_in to{};
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = htonl(dst_ip);
    if (sendto(raw_fd, pkt.data(), pkt.size(), 0, reinterpret_cast<sockaddr*>(&to), sizeof to) < 0)
      std::perror("sendto");
  };

  std::array<std::uint8_t, 65536> buf;
  std::array<pollfd, 2> fds{{{lan_fd, POLLIN, 0}, {wan_fd, POLLIN, 0}}};
  for (;;) {
    if (poll(fds.data(), fds.size(), 1000) < 0) die("poll");
    const auto now = usernat::Clock::now();
    if (auto n = table.expire(now); n > 0 && opt.verbose)
      std::fprintf(stderr, "expired %zu mapping(s)\n", n);

    for (const auto& p : fds) {
      if (!(p.revents & POLLIN)) continue;
      sockaddr_ll from{};
      socklen_t fromlen = sizeof from;
      const ssize_t n = recvfrom(p.fd, buf.data(), buf.size(), 0,
                                 reinterpret_cast<sockaddr*>(&from), &fromlen);
      // PACKET_HOST: addressed to this router. Skips our own sent packets (PACKET_OUTGOING).
      if (n <= 0 || from.sll_pkttype != PACKET_HOST) continue;
      std::span<std::uint8_t> pkt(buf.data(), static_cast<std::size_t>(n));
      const auto udp = usernat::parse_udp(pkt);
      if (!udp) continue;

      if (p.fd == lan_fd) {
        const auto port = table.outbound(udp->src, udp->dst, now);
        if (!port) {
          std::fputs("no free public port, dropping\n", stderr);
          continue;
        }
        if (opt.verbose)
          std::fprintf(stderr, "out %s -> %s as :%u\n", str(udp->src).c_str(),
                       str(udp->dst).c_str(), *port);
        if (usernat::rewrite_src(pkt, {opt.public_ip, *port})) send_raw(pkt, udp->dst.ip);
      } else {
        if (udp->dst.ip != opt.public_ip) continue;
        const auto inner = table.inbound(udp->dst.port, udp->src, now);
        if (opt.verbose)
          std::fprintf(stderr, "in  %s -> :%u %s\n", str(udp->src).c_str(), udp->dst.port,
                       inner ? ("to " + str(*inner)).c_str() : "DROP");
        if (inner && usernat::rewrite_dst(pkt, *inner)) send_raw(pkt, inner->ip);
      }
    }
  }
}
