#include "agent/tls_relay.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <system_error>

#include "relay/framing.hpp"

namespace agent {

TlsRelayShim::TlsRelayShim(const stun::Endpoint& relay_tls, std::chrono::milliseconds timeout)
    : udp_(stun::Endpoint{{127, 0, 0, 1}, 0}) {
  const int family = relay_tls.is_v4() ? AF_INET : AF_INET6;
  tcp_ = socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (tcp_ < 0) throw std::system_error(errno, std::generic_category(), "socket");
  timeval tv{static_cast<time_t>(timeout.count() / 1000),
             static_cast<suseconds_t>((timeout.count() % 1000) * 1000)};
  setsockopt(tcp_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);  // bounds connect() and the handshake
  setsockopt(tcp_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  int one = 1;
  setsockopt(tcp_, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
  const auto sa = stun::to_sockaddr(relay_tls, family);
  if (connect(tcp_, reinterpret_cast<const sockaddr*>(&sa.storage), sa.len) < 0) {
    const int e = errno;
    close(tcp_);
    throw std::system_error(e, std::generic_category(), "connect " + stun::to_string(relay_tls));
  }
  ctx_ = SSL_CTX_new(TLS_client_method());
  SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);
  ssl_ = SSL_new(ctx_);
  SSL_set_fd(ssl_, tcp_);
  if (SSL_connect(ssl_) != 1) {
    SSL_free(ssl_);
    SSL_CTX_free(ctx_);
    close(tcp_);
    throw std::runtime_error("TLS handshake with " + stun::to_string(relay_tls) + " failed");
  }
  // From here on non-blocking: a partly received TLS record must not stall the other direction.
  fcntl(tcp_, F_SETFL, fcntl(tcp_, F_GETFL) | O_NONBLOCK);
  SSL_set_mode(ssl_, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
  thread_ = std::thread([this] { run(); });
}

TlsRelayShim::~TlsRelayShim() {
  stop_ = true;
  if (thread_.joinable()) thread_.join();
  SSL_shutdown(ssl_);
  SSL_free(ssl_);
  SSL_CTX_free(ctx_);
  close(tcp_);
}

stun::Endpoint TlsRelayShim::local() const { return udp_.local_endpoint(); }

void TlsRelayShim::run() {
  // One thread does both directions, so the SSL object is never used concurrently.
  relay::Deframer in;
  std::optional<stun::Endpoint> agent_ep;  // where the agent's socket sends from
  std::uint8_t buf[16384];
  pollfd fds[2] = {{udp_.fd(), POLLIN, 0}, {tcp_, POLLIN, 0}};
  while (!stop_) {
    fds[0].revents = fds[1].revents = 0;
    // SSL may already hold decrypted bytes that poll() cannot see.
    if (SSL_pending(ssl_) == 0 && poll(fds, 2, 100) <= 0) continue;
    if (fds[0].revents & POLLIN) {
      while (auto d = udp_.receive(std::chrono::milliseconds(0))) {
        agent_ep = d->from;
        const auto f = relay::frame(d->bytes);
        // Write it all, waiting for the socket when its send buffer is full.
        for (std::size_t off = 0; off < f.size();) {
          const int n = SSL_write(ssl_, f.data() + off, static_cast<int>(f.size() - off));
          if (n > 0) {
            off += static_cast<std::size_t>(n);
            continue;
          }
          const int err = SSL_get_error(ssl_, n);
          if (err != SSL_ERROR_WANT_WRITE && err != SSL_ERROR_WANT_READ) return;  // relay gone
          pollfd w{tcp_, POLLOUT, 0};
          if (poll(&w, 1, 1000) <= 0) return;
        }
      }
    }
    if ((fds[1].revents & (POLLIN | POLLHUP | POLLERR)) || SSL_pending(ssl_) > 0) {
      const int n = SSL_read(ssl_, buf, sizeof buf);
      if (n <= 0) {
        const int err = SSL_get_error(ssl_, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
        return;  // closed: the agent will notice the relay going quiet
      }
      in.feed(std::span(buf, static_cast<std::size_t>(n)));
      while (auto d = in.next())
        if (agent_ep) udp_.send_to(*d, *agent_ep);
    }
  }
}

}  // namespace agent
