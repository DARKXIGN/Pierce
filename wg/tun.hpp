#pragma once
#include <cstdint>
#include <optional>
#include <span>
#include <string>

// A Linux TUN device: the kernel hands us every IP packet routed to it, and treats what we write
// as packets arriving on it. Needs CAP_NET_ADMIN (root). Addresses and routes are set with `ip`.
namespace wg {

class Tun {
 public:
  // Opens /dev/net/tun and creates (or attaches to) interface `name`, e.g. "pierce0".
  // Throws std::system_error on failure.
  explicit Tun(const std::string& name);
  ~Tun();
  Tun(const Tun&) = delete;
  Tun& operator=(const Tun&) = delete;

  // One IP packet into `buf`; returns its size, or nullopt if none is waiting (non-blocking).
  std::optional<std::size_t> read(std::span<std::uint8_t> buf);
  void write(std::span<const std::uint8_t> packet);
  int fd() const { return fd_; }
  const std::string& name() const { return name_; }

 private:
  int fd_ = -1;
  std::string name_;
};

}  // namespace wg
