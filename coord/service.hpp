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

namespace coord {

struct ServiceOptions {
  std::chrono::milliseconds margin{20};         // added to the punch delay, see timing.hpp
  int pings = 3;                                 // RTT samples per peer; the minimum is used
  std::chrono::milliseconds pong_timeout{1000};  // per sample
  bool verbose = false;
};

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
