#pragma once
#include <chrono>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "stun/message.hpp"

#include <sys/socket.h>

// A minimal blocking UDP socket (IPv4, or dual-stack IPv6), used by every Pierce program.
// Errors (bind failing, etc.) throw std::system_error.
namespace stun {

// "192.0.32.10:3478" or "[2001:db8::2]:3478".
std::optional<Endpoint> parse_endpoint(std::string_view text);
std::optional<Ipv4> parse_ipv4(std::string_view text);
std::string to_string(const Endpoint& ep);  // the same two forms

// Endpoint <-> the C socket API's address structs, for an AF_INET or AF_INET6 socket.
struct SockAddr {
  sockaddr_storage storage{};
  socklen_t len = 0;
};
SockAddr to_sockaddr(const Endpoint& ep, int family);
Endpoint from_sockaddr(const sockaddr* sa);

// The address as the protocol messages carry it: 4 bytes for IPv4, 16 for IPv6.
std::string address_bytes(const Endpoint& ep);
std::optional<Endpoint> from_address_bytes(std::string_view bytes, std::uint16_t port);

struct Datagram {
  std::vector<std::uint8_t> bytes;
  Endpoint from;
};

class UdpSocket {
 public:
  // Binds to `local` (port 0 = let the kernel pick). An IPv4 address gives an IPv4 socket; the
  // default "::" gives a dual-stack socket that talks to IPv4 and IPv6 peers.
  explicit UdpSocket(const Endpoint& local = {});
  ~UdpSocket();
  // The socket owns a file descriptor, so it can be moved but not copied (copying would close
  // the same descriptor twice).
  UdpSocket(UdpSocket&& other) noexcept;
  UdpSocket& operator=(UdpSocket&& other) noexcept;
  UdpSocket(const UdpSocket&) = delete;
  UdpSocket& operator=(const UdpSocket&) = delete;

  void send_to(std::span<const std::uint8_t> bytes, const Endpoint& to);
  // Waits up to `timeout` for one datagram; nullopt on timeout.
  std::optional<Datagram> receive(std::chrono::milliseconds timeout);
  Endpoint local_endpoint() const;
  int fd() const { return fd_; }
  int family() const { return family_; }  // AF_INET or AF_INET6

 private:
  int fd_ = -1;
  int family_ = AF_INET6;
};

}  // namespace stun
