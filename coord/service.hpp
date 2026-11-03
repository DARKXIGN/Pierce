#pragma once
#include <grpcpp/grpcpp.h>

#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "coord.grpc.pb.h"
#include "coord/db.hpp"
#include "relay/protocol.hpp"
#include "stun/message.hpp"

namespace coord {

struct ServiceOptions {
  std::chrono::milliseconds margin{20};         // added to the punch delay, see timing.hpp
  int pings = 3;                                 // RTT samples per peer; the minimum is used
  std::chrono::milliseconds pong_timeout{1000};  // per sample
  bool verbose = false;
  // Relays offered to agents. Empty = no relay fallback.
  std::vector<stun::Endpoint> relays;
  relay::Secret relay_secret;                // shared with the relays
  std::chrono::seconds relay_token_ttl{600};  // how long a relayed path outlives this server
  std::uint16_t relay_tls_port = 0;          // the relays' TCP/TLS port, 0 = none
};

// Index of the relay with the lowest RTT_A + RTT_B. A relay one side did not reach is skipped;
// if no relay was reached by both, the first relay (the configured default) is used.
std::size_t pick_relay(std::size_t relay_count, const std::map<std::uint32_t, std::uint32_t>& rtt_a,
                       const std::map<std::uint32_t, std::uint32_t>& rtt_b);

// Pairs two agents that name each other (A says peer B, B says peer A), measures the RTT to each
// over its own stream, then sends both the other's candidates, a fresh session key and an
// RTT-compensated PunchIn.
class Service final : public pierce::coord::Coord::Service {
 public:
  Service(NodeDb& db, ServiceOptions opt) : db_(db), opt_(opt) {}
  ~Service() override;

  grpc::Status Session(
      grpc::ServerContext* ctx,
      grpc::ServerReaderWriter<pierce::coord::CoordMsg, pierce::coord::AgentMsg>* stream) override;

 private:
  struct Peer;
  void try_pair(const std::shared_ptr<Peer>& peer);
  void run_pairing(std::shared_ptr<Peer> a, std::shared_ptr<Peer> b);

  NodeDb& db_;
  ServiceOptions opt_;
  std::mutex mu_;  // guards peers_, every Peer's ids/candidates/paired, and threads_
  std::map<std::string, std::shared_ptr<Peer>> peers_;
  std::vector<std::jthread> threads_;  // pairing threads; joined in the destructor
};

}  // namespace coord
