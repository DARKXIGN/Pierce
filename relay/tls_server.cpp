#include "relay/tls_server.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <system_error>

#include "stun/udp.hpp"

namespace relay {
namespace {

[[noreturn]] void ssl_fail(const std::string& what) {
  char buf[256];
  ERR_error_string_n(ERR_get_error(), buf, sizeof buf);
  throw std::runtime_error(what + ": " + buf);
}

void set_nonblocking(int fd) { fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK); }

}  // namespace

TlsServer::TlsServer(const stun::Endpoint& listen, const std::string& cert_pem,
                     const std::string& key_pem) {
  ctx_ = SSL_CTX_new(TLS_server_method());
  if (!ctx_) ssl_fail("SSL_CTX_new");
  SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);
  if (SSL_CTX_use_certificate_chain_file(ctx_, cert_pem.c_str()) != 1) ssl_fail("certificate " + cert_pem);
  if (SSL_CTX_use_PrivateKey_file(ctx_, key_pem.c_str(), SSL_FILETYPE_PEM) != 1) ssl_fail("key " + key_pem);
  // SSL_write may write part of a buffer, and the buffer may move between retries (it is a
  // std::vector we erase from).
  SSL_CTX_set_mode(ctx_, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

  const int family = listen.is_v4() ? AF_INET : AF_INET6;
  listen_fd_ = socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (listen_fd_ < 0) throw std::system_error(errno, std::generic_category(), "socket");
  int one = 1;
  setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  const auto sa = stun::to_sockaddr(listen, family);
  if (bind(listen_fd_, reinterpret_cast<const sockaddr*>(&sa.storage), sa.len) < 0 ||
      ::listen(listen_fd_, 64) < 0)
    throw std::system_error(errno, std::generic_category(), "bind/listen " + stun::to_string(listen));
  set_nonblocking(listen_fd_);
}

TlsServer::~TlsServer() {
  while (!conns_.empty()) close(conns_.begin()->first);
  if (listen_fd_ >= 0) ::close(listen_fd_);
  SSL_CTX_free(ctx_);
}

void TlsServer::add_pollfds(std::vector<pollfd>& fds) const {
  fds.push_back({listen_fd_, POLLIN, 0});
  for (const auto& [id, c] : conns_) {
    short ev = POLLIN;
    if (!c.out.empty()) ev |= POLLOUT;
    fds.push_back({c.fd, ev, 0});
  }
}

void TlsServer::accept_all() {
  for (;;) {
    const int fd = accept4(listen_fd_, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (fd < 0) return;  // EAGAIN: no more for now
    if (conns_.size() >= kMaxConnections) {
      ::close(fd);
      continue;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);  // small datagrams, send now
    Conn c;
    c.fd = fd;
    c.ssl = SSL_new(ctx_);
    SSL_set_fd(c.ssl, fd);
    SSL_set_accept_state(c.ssl);
    conns_.emplace(next_id_++ & 0xFFFFFF, std::move(c));  // ids fit stream_endpoint's 24 bits
  }
}

bool TlsServer::flush(Conn& c) {
  while (!c.out.empty()) {
    const int n = SSL_write(c.ssl, c.out.data(), static_cast<int>(c.out.size()));
    if (n > 0) {
      c.out.erase(c.out.begin(), c.out.begin() + n);
      continue;
    }
    const int err = SSL_get_error(c.ssl, n);
    return err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ;  // try again later
  }
  return true;
}

bool TlsServer::step(Conn& c,
                     const std::function<void(std::uint32_t, std::span<const std::uint8_t>)>& cb,
                     std::uint32_t id) {
  if (!c.open) {
    const int rc = SSL_do_handshake(c.ssl);
    if (rc != 1) {
      const int err = SSL_get_error(c.ssl, rc);
      return err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE;
    }
    c.open = true;
  }
  std::uint8_t buf[16384];
  for (;;) {
    const int n = SSL_read(c.ssl, buf, sizeof buf);
    if (n > 0) {
      c.in.feed(std::span(buf, static_cast<std::size_t>(n)));
      while (auto d = c.in.next()) cb(id, *d);
      continue;
    }
    const int err = SSL_get_error(c.ssl, n);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) break;
    return false;  // closed by the peer or a TLS error
  }
  return flush(c);
}

void TlsServer::service(const std::vector<pollfd>& fds,
                        const std::function<void(std::uint32_t, std::span<const std::uint8_t>)>& cb) {
  std::vector<std::uint32_t> dead;
  for (const auto& p : fds) {
    if (!p.revents) continue;
    if (p.fd == listen_fd_) {
      accept_all();
      continue;
    }
    for (auto& [id, c] : conns_) {
      if (c.fd != p.fd) continue;
      if ((p.revents & (POLLERR | POLLHUP)) && !(p.revents & POLLIN)) dead.push_back(id);
      else if (!step(c, cb, id)) dead.push_back(id);
      break;
    }
  }
  for (auto id : dead) close(id);
}

void TlsServer::send(std::uint32_t id, std::span<const std::uint8_t> datagram) {
  auto it = conns_.find(id);
  if (it == conns_.end() || !it->second.open) return;
  auto& c = it->second;
  if (c.out.size() + datagram.size() + 2 > kMaxQueued) return;  // a slow reader loses datagrams, like UDP
  const auto f = frame(datagram);
  c.out.insert(c.out.end(), f.begin(), f.end());
  if (!flush(c)) close(id);
}

void TlsServer::close(std::uint32_t id) {
  auto it = conns_.find(id);
  if (it == conns_.end()) return;
  SSL_free(it->second.ssl);
  ::close(it->second.fd);
  conns_.erase(it);
}

}  // namespace relay
