#pragma once

#include <string>
#include <sqlite3.h>

class AuditLog {
public:
    AuditLog();
    ~AuditLog();

    int open(const std::string& db_path);
    void close();
    int writeEvent(const std::string& action, const std::string& package_name,
                    const std::string& version, const std::string& result,
                    const std::string& reason, const std::string& metadata_hash);
    int verifyChain();

private:
    sqlite3* db_ = nullptr;
    std::string getLastHash();
    int exec(const std::string& sql);
    std::string computeEventHash(const std::string& ts, const std::string& actor,
                                    const std::string& action, const std::string& pkg,
                                    const std::string& ver, const std::string& result,
                                    const std::string& reason, const std::string& meta_hash,
                                    const std::string& prev_hash);
    int initVerifyState();
    int loadVerifyState(std::string& last_hash, int& count);
    int saveVerifyState(const std::string& last_hash, int count);
};
