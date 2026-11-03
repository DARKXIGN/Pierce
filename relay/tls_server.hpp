#pragma once
#include <poll.h>

#include <cstdint>
#include <functional>
#include <map>
#include <span>
#include <string>
#include <vector>

#include "relay/framing.hpp"
#include "stun/message.hpp"

typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;

// The relay's TCP/TLS listener, for agents on networks that block UDP. Single-threaded and
// non-blocking, so it runs in the relay's one poll() loop next to the UDP socket. TLS here hides
// the traffic in ordinary-looking HTTPS and nothing more: what it carries is already WireGuard
// ciphertext, and the relay token does the authentication.
namespace relay {

class TlsServer {
 public:
  TlsServer(const stun::Endpoint& listen, const std::string& cert_pem, const std::string& key_pem);
  ~TlsServer();
  TlsServer(const TlsServer&) = delete;
  TlsServer& operator=(const TlsServer&) = delete;

  // Appends the listening socket and every connection to `fds`, each with the events it needs.
  void add_pollfds(std::vector<pollfd>& fds) const;
  // Handles whatever `fds` reports for our sockets. Calls on_datagram(connection id, bytes) for
  // every complete datagram received.
  void service(const std::vector<pollfd>& fds,
               const std::function<void(std::uint32_t, std::span<const std::uint8_t>)>& on_datagram);
  // Queues a datagram for a connection; dropped silently if it is gone.
  void send(std::uint32_t id, std::span<const std::uint8_t> datagram);
  std::size_t connections() const { return conns_.size(); }

 private:
  struct Conn {
    int fd = -1;
    SSL* ssl = nullptr;
    bool open = false;  // TLS handshake done
    Deframer in;
    std::vector<std::uint8_t> out;  // framed datagrams not yet written
  };
  void accept_all();
  bool step(Conn& c, const std::function<void(std::uint32_t, std::span<const std::uint8_t>)>& cb,
            std::uint32_t id);  // false = close it
  bool flush(Conn& c);
  void close(std::uint32_t id);

  SSL_CTX* ctx_ = nullptr;
  int listen_fd_ = -1;
  std::uint32_t next_id_ = 1;
  std::map<std::uint32_t, Conn> conns_;
  static constexpr std::size_t kMaxConnections = 1024;
  static constexpr std::size_t kMaxQueued = 1 << 20;  // per connection; beyond that, drop
};

}  // namespace relay
