// pierce-coord: the coordination server.
//
//   pierce-coord --listen 203.0.113.10:50051 [--db nodes.sqlite] [--margin-ms 20] [-v]
#include <grpcpp/grpcpp.h>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>

#include "coord/db.hpp"
#include "coord/service.hpp"

namespace {
[[noreturn]] void usage() {
  std::fputs("usage: pierce-coord --listen HOST:PORT [--db FILE] [--margin-ms N] [-v]\n", stderr);
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
    else usage();
  }
  if (listen.empty()) usage();

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
