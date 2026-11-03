#pragma once
#include <mutex>
#include <string>

struct sqlite3;

namespace coord {

// The node table in SQLite: who registered, whom they want to reach, their candidates and the
// last measured RTT. A record for operators and debugging; pairing itself runs from memory.
class NodeDb {
 public:
  explicit NodeDb(const std::string& path);  // ":memory:" for no file
  ~NodeDb();
  NodeDb(const NodeDb&) = delete;
  NodeDb& operator=(const NodeDb&) = delete;

  void upsert_node(const std::string& node_id, const std::string& peer_id);
  void set_candidates(const std::string& node_id, const std::string& candidates_text);
  void set_rtt(const std::string& node_id, double rtt_ms);
  int count_nodes();

 private:
  void exec(const std::string& sql, const std::string& a, const std::string& b = {});

  std::mutex mu_;  // one connection, used from several gRPC threads
  sqlite3* db_ = nullptr;
};

}  // namespace coord
