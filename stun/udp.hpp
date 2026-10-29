#pragma once
#include <chrono>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "stun/message.hpp"

// A minimal blocking IPv4 UDP socket, enough for the STUN server and the NAT detector.
// Errors (bind failing, etc.) throw std::system_error.
namespace stun {

std::optional<Endpoint> parse_endpoint(std::string_view text);  // "192.0.32.10:3478"
std::optional<std::array<std::uint8_t, 4>> parse_ipv4(std::string_view text);
std::string to_string(const Endpoint& ep);

struct Datagram {
  std::vector<std::uint8_t> bytes;
  Endpoint from;
};

class UdpSocket {
 public:
  // Binds to `local` (port 0 = let the kernel pick, ip 0.0.0.0 = any address).
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

 private:
  int fd_ = -1;
};

}  // namespace stun
