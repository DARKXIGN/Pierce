#include "coord/db.hpp"

#include <sqlite3.h>

#include <stdexcept>

namespace coord {

NodeDb::NodeDb(const std::string& path) {
  if (sqlite3_open(path.c_str(), &db_) != SQLITE_OK)
    throw std::runtime_error("sqlite open " + path + ": " + sqlite3_errmsg(db_));
  char* err = nullptr;
  const char* schema =
      "CREATE TABLE IF NOT EXISTS nodes ("
      "  node_id TEXT PRIMARY KEY,"
      "  peer_id TEXT NOT NULL,"
      "  candidates TEXT NOT NULL DEFAULT '',"
      "  rtt_ms REAL,"
      "  last_seen INTEGER NOT NULL)";
  if (sqlite3_exec(db_, schema, nullptr, nullptr, &err) != SQLITE_OK) {
    std::string msg = err ? err : "?";
    sqlite3_free(err);
    throw std::runtime_error("sqlite schema: " + msg);
  }
}

NodeDb::~NodeDb() { sqlite3_close(db_); }

// Runs a statement with up to two text parameters (?1, ?2). Prepared statements keep the values
// out of the SQL text, so a node id like "x'; DROP TABLE nodes" is just a string.
void NodeDb::exec(const std::string& sql, const std::string& a, const std::string& b) {
  std::lock_guard lock(mu_);
  sqlite3_stmt* st = nullptr;
  if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &st, nullptr) != SQLITE_OK)
    throw std::runtime_error(std::string("sqlite prepare: ") + sqlite3_errmsg(db_));
  sqlite3_bind_text(st, 1, a.c_str(), -1, SQLITE_TRANSIENT);
  if (sqlite3_bind_parameter_count(st) >= 2) sqlite3_bind_text(st, 2, b.c_str(), -1, SQLITE_TRANSIENT);
  const int rc = sqlite3_step(st);
  sqlite3_finalize(st);
  if (rc != SQLITE_DONE) throw std::runtime_error(std::string("sqlite step: ") + sqlite3_errmsg(db_));
}

void NodeDb::upsert_node(const std::string& node_id, const std::string& peer_id) {
  exec("INSERT INTO nodes (node_id, peer_id, last_seen) VALUES (?1, ?2, unixepoch()) "
       "ON CONFLICT(node_id) DO UPDATE SET peer_id = ?2, last_seen = unixepoch()",
       node_id, peer_id);
}

void NodeDb::set_candidates(const std::string& node_id, const std::string& candidates_text) {
  exec("UPDATE nodes SET candidates = ?2, last_seen = unixepoch() WHERE node_id = ?1", node_id,
       candidates_text);
}

void NodeDb::set_rtt(const std::string& node_id, double rtt_ms) {
  exec("UPDATE nodes SET rtt_ms = CAST(?2 AS REAL) WHERE node_id = ?1", node_id,
       std::to_string(rtt_ms));
}

int NodeDb::count_nodes() {
  std::lock_guard lock(mu_);
  sqlite3_stmt* st = nullptr;
  sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM nodes", -1, &st, nullptr);
  int n = sqlite3_step(st) == SQLITE_ROW ? sqlite3_column_int(st, 0) : -1;
  sqlite3_finalize(st);
  return n;
}

}  // namespace coord
