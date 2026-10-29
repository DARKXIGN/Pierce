#include "wg/tun.hpp"

#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <system_error>

namespace wg {

Tun::Tun(const std::string& name) {
  fd_ = open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
  if (fd_ < 0) throw std::system_error(errno, std::generic_category(), "open /dev/net/tun");
  ifreq ifr{};
  // IFF_TUN: IP packets (no Ethernet header). IFF_NO_PI: no 4-byte packet-info prefix, so a
  // read returns exactly one IP packet, which is what BoringTun expects.
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
  if (ioctl(fd_, TUNSETIFF, &ifr) < 0) {
    const int e = errno;
    close(fd_);
    throw std::system_error(e, std::generic_category(), "TUNSETIFF " + name);
  }
  name_ = ifr.ifr_name;
}

Tun::~Tun() {
  if (fd_ >= 0) close(fd_);
}

std::optional<std::size_t> Tun::read(std::span<std::uint8_t> buf) {
  const ssize_t n = ::read(fd_, buf.data(), buf.size());
  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) return std::nullopt;
    throw std::system_error(errno, std::generic_category(), "read " + name_);
  }
  return static_cast<std::size_t>(n);
}

void Tun::write(std::span<const std::uint8_t> packet) {
  if (::write(fd_, packet.data(), packet.size()) < 0 && errno != EAGAIN)
    throw std::system_error(errno, std::generic_category(), "write " + name_);
}

}  // namespace wg
