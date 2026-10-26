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

sockaddr_in to_sockaddr(const Endpoint& ep) {
  sockaddr_in sa{};
  sa.sin_family = AF_INET;
  sa.sin_port = htons(ep.port);
  // ipv4 is already in network order (most significant byte first), so copy it as is.
  std::memcpy(&sa.sin_addr, ep.ipv4.data(), 4);
  return sa;
}

Endpoint from_sockaddr(const sockaddr_in& sa) {
  Endpoint ep;
  std::memcpy(ep.ipv4.data(), &sa.sin_addr, 4);
  ep.port = ntohs(sa.sin_port);
  return ep;
}

}  // namespace

std::optional<std::array<std::uint8_t, 4>> parse_ipv4(std::string_view text) {
  in_addr addr{};
  if (inet_pton(AF_INET, std::string(text).c_str(), &addr) != 1) return std::nullopt;
  std::array<std::uint8_t, 4> ip{};
  std::memcpy(ip.data(), &addr, 4);
  return ip;
}

std::optional<Endpoint> parse_endpoint(std::string_view text) {
  const auto colon = text.rfind(':');
  if (colon == std::string_view::npos) return std::nullopt;
  auto ip = parse_ipv4(text.substr(0, colon));
  unsigned port = 0;
  const auto digits = text.substr(colon + 1);
  auto [p, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), port);
  if (!ip || ec != std::errc{} || p != digits.data() + digits.size() || port > 65535)
    return std::nullopt;
  return Endpoint{*ip, static_cast<std::uint16_t>(port)};
}

std::string to_string(const Endpoint& ep) {
  char buf[32];
  std::snprintf(buf, sizeof buf, "%u.%u.%u.%u:%u", ep.ipv4[0], ep.ipv4[1], ep.ipv4[2], ep.ipv4[3],
                ep.port);
  return buf;
}

UdpSocket::UdpSocket(const Endpoint& local) {
  fd_ = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd_ < 0) throw_errno("socket");
  const auto sa = to_sockaddr(local);
  if (bind(fd_, reinterpret_cast<const sockaddr*>(&sa), sizeof sa) < 0) {
    const int saved = errno;
    close(fd_);
    errno = saved;
    throw_errno(("bind " + to_string(local)).c_str());
  }
}

UdpSocket::~UdpSocket() {
  if (fd_ >= 0) close(fd_);
}

UdpSocket::UdpSocket(UdpSocket&& other) noexcept : fd_(std::exchange(other.fd_, -1)) {}

UdpSocket& UdpSocket::operator=(UdpSocket&& other) noexcept {
  if (this != &other) {
    if (fd_ >= 0) close(fd_);
    fd_ = std::exchange(other.fd_, -1);
  }
  return *this;
}

void UdpSocket::send_to(std::span<const std::uint8_t> bytes, const Endpoint& to) {
  const auto sa = to_sockaddr(to);
  if (sendto(fd_, bytes.data(), bytes.size(), 0, reinterpret_cast<const sockaddr*>(&sa),
             sizeof sa) < 0)
    throw_errno("sendto");
}

std::optional<Datagram> UdpSocket::receive(std::chrono::milliseconds timeout) {
  pollfd p{fd_, POLLIN, 0};
  const int ready = poll(&p, 1, static_cast<int>(timeout.count()));
  if (ready < 0) throw_errno("poll");
  if (ready == 0) return std::nullopt;
  Datagram d;
  d.bytes.resize(2048);
  sockaddr_in from{};
  socklen_t len = sizeof from;
  const ssize_t n =
      recvfrom(fd_, d.bytes.data(), d.bytes.size(), 0, reinterpret_cast<sockaddr*>(&from), &len);
  if (n < 0) throw_errno("recvfrom");
  d.bytes.resize(static_cast<std::size_t>(n));
  d.from = from_sockaddr(from);
  return d;
}

Endpoint UdpSocket::local_endpoint() const {
  sockaddr_in sa{};
  socklen_t len = sizeof sa;
  if (getsockname(fd_, reinterpret_cast<sockaddr*>(&sa), &len) < 0) throw_errno("getsockname");
  return from_sockaddr(sa);
}

}  // namespace stun
