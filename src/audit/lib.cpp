#include "lib.hpp"
#include "color.hpp"
#include "crypto/lib.hpp"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

AuditLog::AuditLog() {}

AuditLog::~AuditLog() {
    if (db_) sqlite3_close(db_);
}

int AuditLog::exec(const std::string& sql) {
    char* err = nullptr;
    int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        std::cerr << "sqlite error: " << err << std::endl;
        sqlite3_free(err);
    }
    return rc;
}

int AuditLog::open(const std::string& db_path) {
    int rc = sqlite3_open(db_path.c_str(), &db_);
    if (rc != SQLITE_OK) {
        std::cerr << "failed to open audit db: " << sqlite3_errmsg(db_) << std::endl;
        return 1;
    }

    exec("CREATE TABLE IF NOT EXISTS audit_log ("
         "  id TEXT PRIMARY KEY,"
         "  timestamp TEXT NOT NULL,"
         "  actor TEXT NOT NULL,"
         "  action TEXT NOT NULL,"
         "  package_name TEXT,"
         "  version TEXT,"
         "  result TEXT NOT NULL,"
         "  reason TEXT,"
         "  metadata_hash TEXT,"
         "  previous_event_hash TEXT,"
         "  event_hash TEXT NOT NULL"
         ")");

    return 0;
}

std::string AuditLog::getLastHash() {
    if (!db_) return {};
    std::string sql = "SELECT event_hash FROM audit_log ORDER BY rowid DESC LIMIT 1";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    std::string hash;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* h = (const char*)sqlite3_column_text(stmt, 0);
        if (h) hash = h;
    }
    sqlite3_finalize(stmt);
    return hash;
}

std::string AuditLog::computeEventHash(const std::string& ts, const std::string& actor,
                                           const std::string& action, const std::string& pkg,
                                           const std::string& ver, const std::string& result,
                                           const std::string& reason, const std::string& meta_hash,
                                           const std::string& prev_hash) {
    std::string data = ts + "|" + actor + "|" + action + "|" +
                       pkg + "|" + ver + "|" + result + "|" +
                       reason + "|" + meta_hash + "|" + prev_hash;
    return sha256Data(data);
}

int AuditLog::writeEvent(const std::string& action, const std::string& package_name,
                           const std::string& version, const std::string& result,
                           const std::string& reason, const std::string& metadata_hash) {
    if (!db_) return 1;

    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    std::ostringstream ts;
    ts << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");

    std::string actor = "admin";
    std::string prev_hash = getLastHash();
    std::string event_hash = computeEventHash(ts.str(), actor, action,
                                                 package_name, version, result,
                                                 reason, metadata_hash, prev_hash);
    std::string id = "AUDIT-" + event_hash.substr(0, 6);

    std::string sql = "INSERT INTO audit_log "
                      "(id, timestamp, actor, action, package_name, version, result, reason, metadata_hash, previous_event_hash, event_hash) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, ts.str().c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, actor.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, action.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, package_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, version.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, result.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, reason.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, metadata_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 10, prev_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 11, event_hash.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        std::cerr << "sqlite error writing audit: " << sqlite3_errmsg(db_) << std::endl;
        return 1;
    }

    std::cout << clr::cyan("Audit:") << " " << id << std::endl;
    return 0;
}

int AuditLog::verifyChain() {
    if (!db_) {
        std::cerr << "audit db not open" << std::endl;
        return 1;
    }

    std::string sql = "SELECT timestamp, actor, action, package_name, version, result, reason, "
                      "metadata_hash, previous_event_hash, event_hash, rowid "
                      "FROM audit_log ORDER BY rowid ASC";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);

    std::string expected_prev;
    int checked = 0;
    bool chain_valid = true;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        auto ts = (const char*)sqlite3_column_text(stmt, 0);
        auto actor = (const char*)sqlite3_column_text(stmt, 1);
        auto action = (const char*)sqlite3_column_text(stmt, 2);
        auto pkg = (const char*)sqlite3_column_text(stmt, 3);
        auto ver = (const char*)sqlite3_column_text(stmt, 4);
        auto result = (const char*)sqlite3_column_text(stmt, 5);
        auto reason = (const char*)sqlite3_column_text(stmt, 6);
        auto meta = (const char*)sqlite3_column_text(stmt, 7);
        auto stored_prev = (const char*)sqlite3_column_text(stmt, 8);
        auto stored_hash = (const char*)sqlite3_column_text(stmt, 9);

        std::string s_ts = ts ? ts : "";
        std::string s_actor = actor ? actor : "";
        std::string s_action = action ? action : "";
        std::string s_pkg = pkg ? pkg : "";
        std::string s_ver = ver ? ver : "";
        std::string s_result = result ? result : "";
        std::string s_reason = reason ? reason : "";
        std::string s_meta = meta ? meta : "";
        std::string s_stored_prev = stored_prev ? stored_prev : "";
        std::string s_stored_hash = stored_hash ? stored_hash : "";

        // Check previous hash matches
        if (s_stored_prev != expected_prev) {
            chain_valid = false;
            std::cout << "Chain break at " << s_ts << ": "
                      << "expected previous hash " << expected_prev
                      << " but got " << s_stored_prev << std::endl;
        }

        // Recompute event hash
        std::string computed = computeEventHash(s_ts, s_actor, s_action, s_pkg, s_ver,
                                                   s_result, s_reason, s_meta, s_stored_prev);
        if (computed != s_stored_hash) {
            chain_valid = false;
            std::cout << "Hash mismatch at " << s_ts << std::endl;
        }

        expected_prev = s_stored_hash;
        checked++;
    }
    sqlite3_finalize(stmt);

    if (checked == 0) {
        std::cout << "Audit chain   " << clr::yellow("(empty)") << std::endl;
        return 0;
    }

    if (chain_valid) {
        std::cout << "Audit chain   " << clr::ok("valid") << std::endl;
        std::cout << "Events        " << checked << std::endl;
    } else {
        std::cout << "Audit chain   " << clr::fail("INVALID") << std::endl;
        return 1;
    }

    return 0;
}
