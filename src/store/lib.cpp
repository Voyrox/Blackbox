#include "lib.hpp"
#include "crypto/lib.hpp"
#include <iostream>
#include <sstream>

Store::Store() {}

Store::~Store() {
    if (db_) sqlite3_close(db_);
}

int Store::exec(const std::string& sql) {
    char* err = nullptr;
    int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        std::cerr << "sqlite error: " << err << std::endl;
        sqlite3_free(err);
    }
    return rc;
}

void Store::close() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

int Store::open(const std::string& path) {
    int rc = sqlite3_open(path.c_str(), &db_);
    if (rc != SQLITE_OK) {
        std::cerr << "failed to open database: " << sqlite3_errmsg(db_) << std::endl;
        return 1;
    }

    exec("CREATE TABLE IF NOT EXISTS installed_versions ("
         "  package_name TEXT PRIMARY KEY,"
         "  current_version TEXT NOT NULL,"
         "  previous_version TEXT,"
         "  installed_at TEXT NOT NULL,"
         "  manifest_hash TEXT NOT NULL"
         ")");

    exec("CREATE TABLE IF NOT EXISTS blocked_versions ("
         "  package_name TEXT NOT NULL,"
         "  version TEXT NOT NULL,"
         "  reason TEXT NOT NULL,"
         "  created_at TEXT NOT NULL,"
         "  PRIMARY KEY (package_name, version)"
         ")");

    exec("CREATE TABLE IF NOT EXISTS imported_bundles ("
         "  id TEXT PRIMARY KEY,"
         "  package_name TEXT NOT NULL,"
         "  version TEXT NOT NULL,"
         "  manifest_hash TEXT NOT NULL,"
         "  status TEXT NOT NULL,"
         "  imported_at TEXT NOT NULL"
         ")");

    exec("CREATE TABLE IF NOT EXISTS trusted_vendors ("
         "  name TEXT PRIMARY KEY,"
         "  public_key_pem TEXT NOT NULL,"
         "  fingerprint TEXT NOT NULL,"
         "  added_at TEXT NOT NULL"
         ")");

    return 0;
}

bool Store::isVersionBlocked(const std::string& pkg, const std::string& version) {
    if (!db_) return false;
    std::string sql = "SELECT COUNT(*) FROM blocked_versions WHERE package_name=? AND version=?";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, pkg.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, version.c_str(), -1, SQLITE_TRANSIENT);
    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return count > 0;
}

int Store::addImportedBundle(const std::string& id, const std::string& pkg,
                                const std::string& version, const std::string& manifest_hash,
                                const std::string& status) {
    if (!db_) return 1;
    std::string sql = "INSERT OR IGNORE INTO imported_bundles "
                      "(id, package_name, version, manifest_hash, status, imported_at) "
                      "VALUES (?, ?, ?, ?, ?, datetime('now'))";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, pkg.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, version.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, manifest_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, status.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "sqlite error: " << sqlite3_errmsg(db_) << std::endl;
        return 1;
    }
    return 0;
}

std::string Store::getImportedManifestHash(const std::string& pkg, const std::string& version) {
    if (!db_) return {};
    std::string sql = "SELECT manifest_hash FROM imported_bundles WHERE package_name=? AND version=?";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, pkg.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, version.c_str(), -1, SQLITE_TRANSIENT);
    std::string hash;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* h = (const char*)sqlite3_column_text(stmt, 0);
        if (h) hash = h;
    }
    sqlite3_finalize(stmt);
    return hash;
}

bool Store::bundleImported(const std::string& pkg, const std::string& version) {
    if (!db_) return false;
    std::string sql = "SELECT COUNT(*) FROM imported_bundles "
                      "WHERE package_name=? AND version=?";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, pkg.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, version.c_str(), -1, SQLITE_TRANSIENT);
    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return count > 0;
}

std::string Store::getInstalledVersion(const std::string& pkg) {
    if (!db_) return {};
    std::string sql = "SELECT current_version FROM installed_versions WHERE package_name=?";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, pkg.c_str(), -1, SQLITE_TRANSIENT);
    std::string version;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* v = (const char*)sqlite3_column_text(stmt, 0);
        if (v) version = v;
    }
    sqlite3_finalize(stmt);
    return version;
}

int Store::installPackage(const std::string& pkg, const std::string& version,
                            const std::string& manifest_hash, const std::string& previous) {
    if (!db_) return 1;
    std::string sql = "INSERT OR REPLACE INTO installed_versions "
                      "(package_name, current_version, previous_version, installed_at, manifest_hash) "
                      "VALUES (?, ?, ?, datetime('now'), ?)";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, pkg.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, version.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, previous.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, manifest_hash.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "sqlite error: " << sqlite3_errmsg(db_) << std::endl;
        return 1;
    }
    return 0;
}

std::vector<std::tuple<std::string, std::string, std::string, std::string>> Store::getAllImported() {
    std::vector<std::tuple<std::string, std::string, std::string, std::string>> result;
    if (!db_) return result;
    std::string sql = "SELECT package_name, version, status, imported_at FROM imported_bundles ORDER BY imported_at DESC";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        auto pkg = (const char*)sqlite3_column_text(stmt, 0);
        auto ver = (const char*)sqlite3_column_text(stmt, 1);
        auto st = (const char*)sqlite3_column_text(stmt, 2);
        auto at = (const char*)sqlite3_column_text(stmt, 3);
        result.emplace_back(pkg ? pkg : "", ver ? ver : "",
                            st ? st : "", at ? at : "");
    }
    sqlite3_finalize(stmt);
    return result;
}

int Store::addBlockedVersion(const std::string& pkg, const std::string& version,
                                const std::string& reason) {
    if (!db_) return 1;
    std::string sql = "INSERT OR IGNORE INTO blocked_versions "
                      "(package_name, version, reason, created_at) "
                      "VALUES (?, ?, ?, datetime('now'))";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, pkg.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, version.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, reason.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "sqlite error: " << sqlite3_errmsg(db_) << std::endl;
        return 1;
    }
    return 0;
}

int Store::removeBlockedVersion(const std::string& pkg, const std::string& version) {
    if (!db_) return 1;
    std::string sql = "DELETE FROM blocked_versions WHERE package_name=? AND version=?";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, pkg.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, version.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "sqlite error: " << sqlite3_errmsg(db_) << std::endl;
        return 1;
    }
    return 0;
}

std::vector<std::tuple<std::string, std::string, std::string>> Store::listBlockedVersions() {
    std::vector<std::tuple<std::string, std::string, std::string>> result;
    if (!db_) return result;
    std::string sql = "SELECT package_name, version, reason FROM blocked_versions ORDER BY package_name, version";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        auto pkg = (const char*)sqlite3_column_text(stmt, 0);
        auto ver = (const char*)sqlite3_column_text(stmt, 1);
        auto rsn = (const char*)sqlite3_column_text(stmt, 2);
        result.emplace_back(pkg ? pkg : "", ver ? ver : "", rsn ? rsn : "");
    }
    sqlite3_finalize(stmt);
    return result;
}

std::string Store::getBlockedReason(const std::string& pkg, const std::string& version) {
    if (!db_) return {};
    std::string sql = "SELECT reason FROM blocked_versions WHERE package_name=? AND version=?";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, pkg.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, version.c_str(), -1, SQLITE_TRANSIENT);
    std::string reason;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* r = (const char*)sqlite3_column_text(stmt, 0);
        if (r) reason = r;
    }
    sqlite3_finalize(stmt);
    return reason;
}

int Store::setBundleStatus(const std::string& pkg, const std::string& version,
                              const std::string& status) {
    if (!db_) return 1;
    std::string sql = "UPDATE imported_bundles SET status=? WHERE package_name=? AND version=?";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, status.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, pkg.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, version.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "sqlite error: " << sqlite3_errmsg(db_) << std::endl;
        return 1;
    }
    return 0;
}

std::string Store::getBundleStatus(const std::string& pkg, const std::string& version) {
    if (!db_) return {};
    std::string sql = "SELECT status FROM imported_bundles WHERE package_name=? AND version=?";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, pkg.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, version.c_str(), -1, SQLITE_TRANSIENT);
    std::string status;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* s = (const char*)sqlite3_column_text(stmt, 0);
        if (s) status = s;
    }
    sqlite3_finalize(stmt);
    return status;
}

int Store::beginTransaction() {
    return exec("BEGIN");
}

int Store::commitTransaction() {
    return exec("COMMIT");
}

int Store::rollbackTransaction() {
    return exec("ROLLBACK");
}

std::vector<std::tuple<std::string, std::string, std::string, std::string>> Store::getAllInstalled() {
    std::vector<std::tuple<std::string, std::string, std::string, std::string>> result;
    if (!db_) return result;
    std::string sql = "SELECT package_name, current_version, previous_version, installed_at "
                      "FROM installed_versions ORDER BY package_name";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        auto pkg = (const char*)sqlite3_column_text(stmt, 0);
        auto ver = (const char*)sqlite3_column_text(stmt, 1);
        auto prev = (const char*)sqlite3_column_text(stmt, 2);
        auto at = (const char*)sqlite3_column_text(stmt, 3);
        result.emplace_back(pkg ? pkg : "", ver ? ver : "",
                            prev ? prev : "", at ? at : "");
    }
    sqlite3_finalize(stmt);
    return result;
}

int Store::addTrustedVendor(const std::string& name, const std::string& public_key_pem) {
    if (!db_) return 1;
    std::string fp = sha256Data(public_key_pem);
    std::string sql = "INSERT OR REPLACE INTO trusted_vendors "
                      "(name, public_key_pem, fingerprint, added_at) "
                      "VALUES (?, ?, ?, datetime('now'))";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, public_key_pem.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, fp.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "sqlite error: " << sqlite3_errmsg(db_) << std::endl;
        return 1;
    }
    return 0;
}

int Store::removeTrustedVendor(const std::string& name) {
    if (!db_) return 1;
    std::string sql = "DELETE FROM trusted_vendors WHERE name=?";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "sqlite error: " << sqlite3_errmsg(db_) << std::endl;
        return 1;
    }
    return 0;
}

std::vector<TrustedVendor> Store::listTrustedVendors() {
    std::vector<TrustedVendor> result;
    if (!db_) return result;
    std::string sql = "SELECT name, public_key_pem, fingerprint, added_at FROM trusted_vendors ORDER BY name";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        TrustedVendor v;
        auto n = (const char*)sqlite3_column_text(stmt, 0);
        auto k = (const char*)sqlite3_column_text(stmt, 1);
        auto f = (const char*)sqlite3_column_text(stmt, 2);
        auto a = (const char*)sqlite3_column_text(stmt, 3);
        v.name = n ? n : "";
        v.public_key_pem = k ? k : "";
        v.fingerprint = f ? f : "";
        v.added_at = a ? a : "";
        result.push_back(v);
    }
    sqlite3_finalize(stmt);
    return result;
}

std::vector<std::pair<std::string, std::string>> Store::getAllVendorKeys() {
    std::vector<std::pair<std::string, std::string>> result;
    if (!db_) return result;
    std::string sql = "SELECT name, public_key_pem FROM trusted_vendors";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        auto n = (const char*)sqlite3_column_text(stmt, 0);
        auto k = (const char*)sqlite3_column_text(stmt, 1);
        result.emplace_back(n ? n : "", k ? k : "");
    }
    sqlite3_finalize(stmt);
    return result;
}
