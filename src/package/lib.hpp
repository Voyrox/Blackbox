#pragma once

#include <string>
#include <vector>

class Store;
class AuditLog;

struct Manifest {
    std::string package_name;
    std::string version;
    std::string build_id;
    std::string target_os = "linux";
    std::string target_arch = "x86_64";
    std::string payload_hash;
    std::string sbom_hash;
    std::string minimum_allowed_version = "0.0.0";
    bool requires_reboot = false;
    std::vector<std::pair<std::string, std::string>> dependencies;
    std::string created_by = "blackbox";
    std::string expires_at;
};

std::string iso8601Now();
bool versionLessThan(const std::string& a, const std::string& b);

int createPackage(const std::string& name, const std::string& version,
                   const std::string& payload_path, const std::string& sbom_path,
                   const std::string& output_path);

int signPackage(const std::string& pkg_path, const std::string& key_path);

int verifyPackage(const std::string& pkg_path,
                   Store* store = nullptr, AuditLog* audit = nullptr);

int approvePackage(const std::string& pkg_name, const std::string& version,
                    Store* store = nullptr, AuditLog* audit = nullptr);
