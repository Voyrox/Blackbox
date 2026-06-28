#include "package/lib.hpp"
#include "color.hpp"
#include "crypto/lib.hpp"
#include "store/lib.hpp"
#include "audit/lib.hpp"
#include "policy/lib.hpp"

#include <archive.h>
#include <archive_entry.h>

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

static std::string readArchiveEntry(struct archive* a, const std::string& name) {
    struct archive_entry* entry;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        std::string pathname = archive_entry_pathname(entry);
        if (pathname == name) {
            std::ostringstream out;
            char buf[8192];
            ssize_t len;
            while ((len = archive_read_data(a, buf, sizeof(buf))) > 0)
                out.write(buf, len);
            return out.str();
        }
        archive_read_data_skip(a);
    }
    return {};
}

static std::string extractJsonString(const std::string& json, const std::string& key) {
    auto pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return {};
    pos = json.find(':', pos);
    if (pos == std::string::npos) return {};
    pos = json.find_first_of("\"", pos);
    if (pos == std::string::npos) return {};
    auto start = pos + 1;
    auto end = json.find("\"", start);
    if (end == std::string::npos) return {};
    return json.substr(start, end - start);
}

static std::vector<std::pair<std::string, std::string>> extractDependencies(const std::string& json) {
    std::vector<std::pair<std::string, std::string>> deps;
    auto arr_start = json.find("\"dependencies\"");
    if (arr_start == std::string::npos) return deps;
    arr_start = json.find('[', arr_start);
    if (arr_start == std::string::npos) return deps;
    auto arr_end = json.find(']', arr_start);
    if (arr_end == std::string::npos) return deps;
    std::string arr = json.substr(arr_start + 1, arr_end - arr_start - 1);
    size_t pos = 0;
    while (true) {
        auto obj_start = arr.find('{', pos);
        if (obj_start == std::string::npos) break;
        auto obj_end = arr.find('}', obj_start);
        if (obj_end == std::string::npos) break;
        std::string obj = arr.substr(obj_start, obj_end - obj_start + 1);
        std::string name = extractJsonString(obj, "name");
        std::string version = extractJsonString(obj, "version");
        if (!name.empty())
            deps.emplace_back(name, version);
        pos = obj_end + 1;
    }
    return deps;
}

static bool isMetadataExpired(const std::string& expires_at) {
    if (expires_at.empty()) return false;
    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm expiry_tm = {};
    std::istringstream ss(expires_at);
    ss >> std::get_time(&expiry_tm, "%Y-%m-%dT%H:%M:%SZ");
    if (ss.fail()) return false;
    auto expiry_time = std::mktime(&expiry_tm);
    return now > expiry_time;
}

int verifyPackage(const std::string& pkg_path,
                   Store* store, AuditLog* audit) {
    std::string sig_path = pkg_path + ".sig";

    std::string vendor_name;
    bool sig_valid = false;
    if (store) {
        auto keys = store->getAllVendorKeys();
        for (const auto& [name, pem] : keys) {
            if (verifyFileWithKey(pkg_path, sig_path, pem)) {
                sig_valid = true;
                vendor_name = name;
                break;
            }
        }
    } else {
        sig_valid = verifyFile(pkg_path, sig_path, "keys/release.key.pub");
    }

    struct archive* a = archive_read_new();
    archive_read_support_filter_gzip(a);
    archive_read_support_format_tar(a);

    if (archive_read_open_filename(a, pkg_path.c_str(), 8192) != ARCHIVE_OK) {
        std::cerr << "error: cannot read package" << std::endl;
        return 1;
    }

    std::string manifest_str = readArchiveEntry(a, "metadata/manifest.json");
    std::string sbom_str = readArchiveEntry(a, "metadata/sbom.spdx.json");
    archive_read_close(a);
    archive_read_free(a);

    std::string pkg_name, version, manifest_hash, expires_at;
    bool hash_matches = false, sbom_present = false, sbom_hash_matches = false;
    bool expired = false, downgrade = false;
    bool deps_blocked_flag = false;
    std::string installed_version;
    std::vector<DepCheck> deps_checked;

    if (!manifest_str.empty()) {
        pkg_name = extractJsonString(manifest_str, "package_name");
        version = extractJsonString(manifest_str, "version");
        std::string manifest_payload_hash = extractJsonString(manifest_str, "payload_hash");
        std::string manifest_sbom_hash = extractJsonString(manifest_str, "sbom_hash");
        expires_at = extractJsonString(manifest_str, "expires_at");
        manifest_hash = sha256Data(manifest_str);

        std::string expected_payload_hash;
        if (manifest_payload_hash.rfind("sha256:", 0) == 0)
            expected_payload_hash = manifest_payload_hash.substr(7);
        hash_matches = !expected_payload_hash.empty();

        sbom_present = !sbom_str.empty();
        if (sbom_present) {
            std::string expected_sbom_hash;
            if (manifest_sbom_hash.rfind("sha256:", 0) == 0)
                expected_sbom_hash = manifest_sbom_hash.substr(7);
            std::string actual_sbom_hash = sha256Data(sbom_str);
            sbom_hash_matches = (actual_sbom_hash == expected_sbom_hash);
        }

        expired = isMetadataExpired(expires_at);

        auto raw_deps = extractDependencies(manifest_str);
        deps_checked = checkDependencies(raw_deps, store);
        for (const auto& dc : deps_checked) {
            if (dc.blocked) { deps_blocked_flag = true; break; }
        }

        if (store) {
            installed_version = store->getInstalledVersion(pkg_name);
            if (!installed_version.empty() && versionLessThan(version, installed_version))
                downgrade = true;
        }
    }

    std::cout << std::endl;
    std::cout << "  Signature    " << (sig_valid ? clr::ok("valid") : clr::fail("INVALID"));
    if (sig_valid && !vendor_name.empty())
        std::cout << " (" << vendor_name << ")";
    std::cout << std::endl;
    std::cout << "  Bundle       " << (manifest_str.empty() ? clr::fail("missing") : clr::bold(pkg_name + " " + version)) << std::endl;
    if (!manifest_str.empty()) {
        std::cout << "  Payload hash " << (hash_matches ? clr::ok("valid") : clr::fail("INVALID")) << std::endl;
        std::cout << "  SBOM         " << (sbom_present ? clr::ok("present") : clr::fail("MISSING")) << std::endl;
        if (sbom_present)
            std::cout << "  SBOM hash    " << (sbom_hash_matches ? clr::ok("valid") : clr::fail("INVALID")) << std::endl;
        std::cout << "  Expiry       " << (expired ? clr::fail("EXPIRED") : clr::ok("valid")) << std::endl;
    }
    if (store)
        std::cout << "  Rollback     " << (downgrade ? clr::fail("BLOCKED") : clr::ok("passed")) << std::endl;
    if (!manifest_str.empty() && store)
        std::cout << "  Dependencies " << (deps_blocked_flag ? clr::fail("BLOCKED") : clr::ok("all clear")) << std::endl;

    bool manifest_ok = !manifest_str.empty() && hash_matches && sbom_present && sbom_hash_matches && !expired;
    bool all_pass = sig_valid && manifest_ok && !downgrade && !deps_blocked_flag;

    if (all_pass) {
        std::cout << std::endl;
        std::cout << "  " << clr::ok("Status: imported and pending approval") << std::endl;

        if (store) {
            store->addImportedBundle(iso8601Now(), pkg_name, version,
                                       manifest_hash, "pending");
        }
        if (audit)
            audit->writeEvent("PACKAGE_IMPORTED", pkg_name, version,
                               "success", "", manifest_hash);
        return 0;
    }

    std::cout << std::endl;
    std::cout << "  " << clr::fail("Status: rejected") << std::endl;
    std::string reason;
    if (!sig_valid) { std::cout << "    - " << clr::red("invalid signature") << std::endl; reason = "invalid signature"; }
    if (!manifest_ok) {
        if (manifest_str.empty()) { std::cout << "    - " << clr::red("manifest not found") << std::endl; reason = "manifest missing"; }
        if (!hash_matches) { std::cout << "    - " << clr::red("payload hash mismatch") << std::endl; reason = "payload hash mismatch"; }
        if (!sbom_present) { std::cout << "    - " << clr::red("SBOM missing") << std::endl; reason = "sbom missing"; }
        if (!sbom_hash_matches) { std::cout << "    - " << clr::red("SBOM hash mismatch") << std::endl; reason = "sbom hash mismatch"; }
        if (expired) { std::cout << "    - " << clr::red("metadata expired") << std::endl; reason = "metadata expired"; }
    }
    if (downgrade) {
        std::cout << "    - " << clr::red("version " + version + " is older than installed " + installed_version + " (downgrade blocked)") << std::endl;
        reason = "downgrade blocked";
    }
    if (deps_blocked_flag) {
        for (const auto& dc : deps_checked) {
            if (dc.blocked) {
                std::cout << "    - " << clr::red("dependency " + dc.name + " " + dc.version + " is blocked: " + dc.reason) << std::endl;
            }
        }
        if (reason.empty()) reason = "blocked dependency";
        else reason += "; blocked dependency";
    }

    if (audit) {
        if (downgrade)
            audit->writeEvent("ROLLBACK_BLOCKED", pkg_name, version,
                               "failed", reason, manifest_hash);
        else
            audit->writeEvent("PACKAGE_REJECTED", pkg_name, version,
                               "failed", reason, manifest_hash);
    }
    return 1;
}
