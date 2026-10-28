// pierce-coord: the coordination server.
//
//   pierce-coord --listen 203.0.113.10:50051 [--db nodes.sqlite] [--margin-ms 20] [-v]
//                [--relay IP:PORT ... --relay-secret HEX [--relay-token-ttl SEC]]
//
// Each --relay adds one relay to offer; the first is the default when RTTs are missing.
#include <grpcpp/grpcpp.h>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>

#include "coord/db.hpp"
#include "coord/service.hpp"
#include "stun/udp.hpp"

namespace {
[[noreturn]] void usage() {
  std::fputs(
      "usage: pierce-coord --listen HOST:PORT [--db FILE] [--margin-ms N] [-v]\n"
      "                    [--relay IP:PORT ... --relay-secret HEX [--relay-token-ttl SEC]]\n",
      stderr);
  std::exit(2);
}
}  // namespace

int main(int argc, char** argv) try {
  std::string listen, db_path = ":memory:";
  coord::ServiceOptions opt;
  for (int i = 1; i < argc; ++i) {
    std::string_view a = argv[i];
    auto value = [&] {
      if (i + 1 >= argc) usage();
      return std::string(argv[++i]);
    };
    if (a == "--listen") listen = value();
    else if (a == "--db") db_path = value();
    else if (a == "--margin-ms") opt.margin = std::chrono::milliseconds(std::atoi(value().c_str()));
    else if (a == "-v") opt.verbose = true;
    else if (a == "--relay") {
      auto ep = stun::parse_endpoint(value());
      if (!ep) usage();
      opt.relays.push_back(*ep);
    } else if (a == "--relay-secret") {
      auto sec = relay::secret_from_hex(value());
      if (!sec) usage();
      opt.relay_secret = *sec;
    } else if (a == "--relay-token-ttl") opt.relay_token_ttl = std::chrono::seconds(std::atoi(value().c_str()));
    else usage();
  }
  if (listen.empty() || (!opt.relays.empty() && opt.relay_secret.empty())) usage();

  coord::NodeDb db(db_path);
  coord::Service service(db, opt);
  grpc::ServerBuilder builder;
  // Plain-text gRPC: the threat model leaves coordination-server auth out of scope for now.
  builder.AddListeningPort(listen, grpc::InsecureServerCredentials());
  builder.RegisterService(&service);
  auto server = builder.BuildAndStart();
  if (!server) {
    std::fprintf(stderr, "pierce-coord: cannot listen on %s\n", listen.c_str());
    return 1;
  }
  std::fprintf(stderr, "pierce-coord: listening on %s, db %s\n", listen.c_str(), db_path.c_str());
  server->Wait();
} catch (const std::exception& e) {
  std::fprintf(stderr, "pierce-coord: %s\n", e.what());
  return 1;
}
