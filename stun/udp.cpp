#include "stun/udp.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <charconv>
#include <cstdio>
#include <system_error>
#include <utility>

namespace stun {
namespace {

[[noreturn]] void throw_errno(const char* what) {
  throw std::system_error(errno, std::generic_category(), what);
}

}  // namespace

SockAddr to_sockaddr(const Endpoint& ep, int family) {
  SockAddr out;
  if (family == AF_INET) {
    auto& sa = reinterpret_cast<sockaddr_in&>(out.storage);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(ep.port);
    // The address is already in network order (most significant byte first): copy it as is.
    std::memcpy(&sa.sin_addr, ep.ip.data() + 12, 4);
    out.len = sizeof sa;
  } else {
    // On an IPv6 socket an IPv4 peer is addressed in its mapped form, which Endpoint already is.
    auto& sa = reinterpret_cast<sockaddr_in6&>(out.storage);
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons(ep.port);
    std::memcpy(&sa.sin6_addr, ep.ip.data(), 16);
    out.len = sizeof sa;
  }
  return out;
}

Endpoint from_sockaddr(const sockaddr* sa) {
  if (sa->sa_family == AF_INET) {
    const auto* in = reinterpret_cast<const sockaddr_in*>(sa);
    Ipv4 ip;
    std::memcpy(ip.data(), &in->sin_addr, 4);
    return Endpoint{ip, ntohs(in->sin_port)};
  }
  const auto* in6 = reinterpret_cast<const sockaddr_in6*>(sa);
  Ipv6 ip;
  std::memcpy(ip.data(), &in6->sin6_addr, 16);
  return Endpoint::v6(ip, ntohs(in6->sin6_port));
}

std::string address_bytes(const Endpoint& ep) {
  if (ep.is_v4()) return std::string(ep.ip.begin() + 12, ep.ip.end());
  return std::string(ep.ip.begin(), ep.ip.end());
}

std::optional<Endpoint> from_address_bytes(std::string_view b, std::uint16_t port) {
  if (b.size() == 4) return Endpoint{Ipv4{std::uint8_t(b[0]), std::uint8_t(b[1]), std::uint8_t(b[2]), std::uint8_t(b[3])}, port};
  if (b.size() != 16) return std::nullopt;
  Ipv6 ip;
  std::copy(b.begin(), b.end(), ip.begin());
  return Endpoint::v6(ip, port);
}

std::optional<Ipv4> parse_ipv4(std::string_view text) {
  in_addr addr{};
  if (inet_pton(AF_INET, std::string(text).c_str(), &addr) != 1) return std::nullopt;
  Ipv4 ip{};
  std::memcpy(ip.data(), &addr, 4);
  return ip;
}

std::optional<Endpoint> parse_endpoint(std::string_view text) {
  const auto colon = text.rfind(':');
  if (colon == std::string_view::npos) return std::nullopt;
  unsigned port = 0;
  const auto digits = text.substr(colon + 1);
  auto [p, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), port);
  if (ec != std::errc{} || p != digits.data() + digits.size() || port > 65535) return std::nullopt;
  const auto host = text.substr(0, colon);
  // IPv6 is written in brackets, "[2001:db8::2]:3478", so the port's colon is unambiguous.
  if (host.size() > 2 && host.front() == '[' && host.back() == ']') {
    in6_addr a{};
    if (inet_pton(AF_INET6, std::string(host.substr(1, host.size() - 2)).c_str(), &a) != 1)
      return std::nullopt;
    Ipv6 ip;
    std::memcpy(ip.data(), &a, 16);
    return Endpoint::v6(ip, static_cast<std::uint16_t>(port));
  }
  auto ip = parse_ipv4(host);
  if (!ip) return std::nullopt;
  return Endpoint{*ip, static_cast<std::uint16_t>(port)};
}

std::string to_string(const Endpoint& ep) {
  char buf[64];
  if (ep.is_v4()) {
    const auto a = ep.v4();
    std::snprintf(buf, sizeof buf, "%u.%u.%u.%u:%u", a[0], a[1], a[2], a[3], ep.port);
    return buf;
  }
  char text[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, ep.ip.data(), text, sizeof text);
  std::snprintf(buf, sizeof buf, "[%s]:%u", text, ep.port);
  return buf;
}

UdpSocket::UdpSocket(const Endpoint& local) {
  // An IPv4 address gets an IPv4 socket. Anything else, including the default "::", gets an
  // IPv6 socket with IPV6_V6ONLY off: dual-stack, so the agent's one socket reaches IPv4 and
  // IPv6 peers alike. If the kernel has IPv6 switched off, fall back to IPv4 only.
  Endpoint bind_to = local;
  family_ = local.is_v4() ? AF_INET : AF_INET6;
  fd_ = socket(family_, SOCK_DGRAM, 0);
  if (fd_ < 0 && family_ == AF_INET6 && errno == EAFNOSUPPORT && local == Endpoint{}) {
    family_ = AF_INET;
    bind_to = Endpoint{Ipv4{}, 0};
    fd_ = socket(AF_INET, SOCK_DGRAM, 0);
  }
  if (fd_ < 0) throw_errno("socket");
  if (family_ == AF_INET6) {
    int off = 0;
    setsockopt(fd_, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof off);
  }
  const auto sa = to_sockaddr(bind_to, family_);
  if (bind(fd_, reinterpret_cast<const sockaddr*>(&sa.storage), sa.len) < 0) {
    const int saved = errno;
    close(fd_);
    errno = saved;
    throw_errno(("bind " + to_string(local)).c_str());
  }
}

UdpSocket::~UdpSocket() {
  if (fd_ >= 0) close(fd_);
}

UdpSocket::UdpSocket(UdpSocket&& other) noexcept
    : fd_(std::exchange(other.fd_, -1)), family_(other.family_) {}

UdpSocket& UdpSocket::operator=(UdpSocket&& other) noexcept {
  if (this != &other) {
    if (fd_ >= 0) close(fd_);
    fd_ = std::exchange(other.fd_, -1);
    family_ = other.family_;
  }
  return *this;
}

void UdpSocket::send_to(std::span<const std::uint8_t> bytes, const Endpoint& to) {
  if (family_ == AF_INET && !to.is_v4()) {
    errno = EAFNOSUPPORT;  // an IPv6 destination from an IPv4-only socket
    throw_errno("sendto");
  }
  const auto sa = to_sockaddr(to, family_);
  if (sendto(fd_, bytes.data(), bytes.size(), 0, reinterpret_cast<const sockaddr*>(&sa.storage),
             sa.len) < 0)
    throw_errno("sendto");
}

std::optional<Datagram> UdpSocket::receive(std::chrono::milliseconds timeout) {
  pollfd p{fd_, POLLIN, 0};
  const int ready = poll(&p, 1, static_cast<int>(timeout.count()));
  if (ready < 0) throw_errno("poll");
  if (ready == 0) return std::nullopt;
  Datagram d;
  d.bytes.resize(2048);
  sockaddr_storage from{};
  socklen_t len = sizeof from;
  const ssize_t n =
      recvfrom(fd_, d.bytes.data(), d.bytes.size(), 0, reinterpret_cast<sockaddr*>(&from), &len);
  if (n < 0) throw_errno("recvfrom");
  d.bytes.resize(static_cast<std::size_t>(n));
  d.from = from_sockaddr(reinterpret_cast<const sockaddr*>(&from));
  return d;
}

Endpoint UdpSocket::local_endpoint() const {
  sockaddr_storage sa{};
  socklen_t len = sizeof sa;
  if (getsockname(fd_, reinterpret_cast<sockaddr*>(&sa), &len) < 0) throw_errno("getsockname");
  return from_sockaddr(reinterpret_cast<const sockaddr*>(&sa));
}

}  // namespace stun
