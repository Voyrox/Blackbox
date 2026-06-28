#pragma once

#include <string>
#include <vector>
#include <tuple>
#include <sqlite3.h>

class Store {
public:
    Store();
    ~Store();

    int open(const std::string& path);
    bool isVersionBlocked(const std::string& pkg, const std::string& version);

    int addImportedBundle(const std::string& id, const std::string& pkg,
                            const std::string& version, const std::string& manifest_hash,
                            const std::string& status);
    bool bundleImported(const std::string& pkg, const std::string& version);
    std::string getImportedManifestHash(const std::string& pkg, const std::string& version);
    std::vector<std::tuple<std::string, std::string, std::string, std::string>> getAllImported();

    std::string getInstalledVersion(const std::string& pkg);
    int installPackage(const std::string& pkg, const std::string& version,
                        const std::string& manifest_hash, const std::string& previous);
    std::vector<std::tuple<std::string, std::string, std::string, std::string>> getAllInstalled();

    int addBlockedVersion(const std::string& pkg, const std::string& version, const std::string& reason);
    int removeBlockedVersion(const std::string& pkg, const std::string& version);
    std::vector<std::tuple<std::string, std::string, std::string>> listBlockedVersions();
    std::string getBlockedReason(const std::string& pkg, const std::string& version);
    int setBundleStatus(const std::string& pkg, const std::string& version, const std::string& status);
    std::string getBundleStatus(const std::string& pkg, const std::string& version);
    int beginTransaction();
    int commitTransaction();
    int rollbackTransaction();

private:
    sqlite3* db_ = nullptr;
    int exec(const std::string& sql);
};
