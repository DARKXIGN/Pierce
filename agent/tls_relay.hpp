#pragma once
#include <atomic>
#include <thread>

#include "stun/udp.hpp"

typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;

// The TCP/TLS fallback to the relay, for networks that block UDP. Instead of teaching the
// puncher and the data plane a second transport, this shim makes the TLS relay look like a UDP
// relay at a loopback address: datagrams the agent sends to local() go to the relay inside the
// TLS stream (relay/framing.hpp), and datagrams the relay sends back arrive from local().
namespace agent {

class TlsRelayShim {
 public:
  // Connects to the relay's TLS port and does the TLS handshake (up to `timeout`). Throws on
  // failure. The relay's certificate is not checked: everything inside is WireGuard ciphertext
  // or token-authenticated relay control, so a man in the middle learns nothing a relay could
  // not, and TLS is only there to get through firewalls that let HTTPS out.
  TlsRelayShim(const stun::Endpoint& relay_tls, std::chrono::milliseconds timeout);
  ~TlsRelayShim();
  TlsRelayShim(const TlsRelayShim&) = delete;
  TlsRelayShim& operator=(const TlsRelayShim&) = delete;

  stun::Endpoint local() const;  // send relay datagrams here

 private:
  void run();

  SSL_CTX* ctx_ = nullptr;
  SSL* ssl_ = nullptr;
  int tcp_ = -1;
  stun::UdpSocket udp_;  // 127.0.0.1, ephemeral port
  std::atomic<bool> stop_ = false;
  std::thread thread_;
};

}  // namespace agent
