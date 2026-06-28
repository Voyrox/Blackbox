#include "package/lib.hpp"
#include "color.hpp"
#include "crypto/lib.hpp"
#include "sbom/lib.hpp"

#include <archive.h>
#include <archive_entry.h>

#include <chrono>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>

namespace fs = std::filesystem;

static std::string formatExpiry() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now + std::chrono::hours(90 * 24));
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    std::ostringstream out;
    out << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return out.str();
}

static std::string buildManifestJson(const Manifest& m) {
    std::ostringstream j;
    j << "{\n";
    j << "  \"package_name\": \"" << m.package_name << "\",\n";
    j << "  \"version\": \"" << m.version << "\",\n";
    j << "  \"build_id\": \"" << m.build_id << "\",\n";
    j << "  \"target_os\": \"" << m.target_os << "\",\n";
    j << "  \"target_arch\": \"" << m.target_arch << "\",\n";
    j << "  \"payload_hash\": \"sha256:" << m.payload_hash << "\",\n";
    j << "  \"sbom_hash\": \"sha256:" << m.sbom_hash << "\",\n";
    j << "  \"minimum_allowed_version\": \"" << m.minimum_allowed_version << "\",\n";
    j << "  \"requires_reboot\": " << (m.requires_reboot ? "true" : "false") << ",\n";
    j << "  \"dependencies\": [\n";
    for (size_t i = 0; i < m.dependencies.size(); i++) {
        j << "    {\n";
        j << "      \"name\": \"" << m.dependencies[i].first << "\",\n";
        j << "      \"version\": \"" << m.dependencies[i].second << "\"\n";
        j << "    }";
        if (i + 1 < m.dependencies.size()) j << ",";
        j << "\n";
    }
    j << "  ],\n";
    j << "  \"created_by\": \"" << m.created_by << "\",\n";
    j << "  \"expires_at\": \"" << m.expires_at << "\"\n";
    j << "}\n";
    return j.str();
}

static std::string hashPayloadDirectory(const fs::path& dir) {
    std::map<std::string, std::string> file_hashes;

    for (const auto& entry : fs::recursive_directory_iterator(dir)) {
        if (!entry.is_regular_file()) continue;
        auto rel = fs::relative(entry.path(), dir).generic_string();
        auto h = sha256File(entry.path().string());
        if (h.empty()) {
            std::cerr << "error: cannot read " << rel << std::endl;
            return {};
        }
        file_hashes[rel] = h;
    }

    std::ostringstream combined;
    for (const auto& [path, hash] : file_hashes) {
        combined << path << ":" << hash << "\n";
    }
    return sha256Data(combined.str());
}

static int writeBufferToArchive(struct archive* a, const std::string& name,
                                    const char* data, size_t size) {
    struct archive_entry* entry = archive_entry_new();
    archive_entry_set_pathname(entry, name.c_str());
    archive_entry_set_size(entry, size);
    archive_entry_set_filetype(entry, AE_IFREG);
    archive_entry_set_perm(entry, 0644);
    archive_entry_set_mtime(entry, time(nullptr), 0);

    int r = archive_write_header(a, entry);
    if (r != ARCHIVE_OK) {
        std::cerr << "archive error: " << archive_error_string(a) << std::endl;
        archive_entry_free(entry);
        return 1;
    }
    if (size > 0)
        archive_write_data(a, data, size);
    archive_entry_free(entry);
    return 0;
}

static int writeFileToArchive(struct archive* a, const std::string& archive_name,
                                  const std::string& file_on_disk) {
    std::ifstream f(file_on_disk, std::ios::binary);
    if (!f) {
        std::cerr << "error: cannot open " << file_on_disk << std::endl;
        return 1;
    }

    f.seekg(0, std::ios::end);
    auto size = f.tellg();
    f.seekg(0, std::ios::beg);

    struct archive_entry* entry = archive_entry_new();
    archive_entry_set_pathname(entry, archive_name.c_str());
    archive_entry_set_size(entry, size);
    archive_entry_set_filetype(entry, AE_IFREG);
    archive_entry_set_perm(entry, 0644);
    archive_entry_set_mtime(entry, time(nullptr), 0);

    int r = archive_write_header(a, entry);
    if (r != ARCHIVE_OK) {
        std::cerr << "archive error: " << archive_error_string(a) << std::endl;
        archive_entry_free(entry);
        return 1;
    }

    char buf[8192];
    while (f.read(buf, sizeof(buf)) || f.gcount()) {
        archive_write_data(a, buf, f.gcount());
    }
    archive_entry_free(entry);
    return 0;
}

static int addPayloadFiles(struct archive* a, const fs::path& payload_dir) {
    for (const auto& entry : fs::recursive_directory_iterator(payload_dir)) {
        auto rel = fs::relative(entry.path(), payload_dir).generic_string();
        auto archive_name = "payload/" + rel;

        if (entry.is_directory()) {
            struct archive_entry* ae = archive_entry_new();
            archive_entry_set_pathname(ae, archive_name.c_str());
            archive_entry_set_filetype(ae, AE_IFDIR);
            archive_entry_set_perm(ae, 0755);
            int r = archive_write_header(a, ae);
            archive_entry_free(ae);
            if (r != ARCHIVE_OK) {
                std::cerr << "archive error: " << archive_error_string(a) << std::endl;
                return 1;
            }
        } else if (entry.is_regular_file()) {
            if (writeFileToArchive(a, archive_name, entry.path().string()))
                return 1;
        }
    }
    return 0;
}

int createPackage(const std::string& name, const std::string& version,
                   const std::string& payload_path, const std::string& sbom_path,
                   const std::string& output_path) {

    fs::path payload_dir(payload_path);
    if (!fs::exists(payload_dir)) {
        std::cerr << "error: payload path does not exist: " << payload_path << std::endl;
        return 1;
    }

    std::string sbom_content = readSbom(sbom_path);
    if (sbom_content.empty()) {
        std::cerr << "error: cannot read SBOM file: " << sbom_path << std::endl;
        return 1;
    }

    std::string sbom_hash = sha256Data(sbom_content);
    std::string payload_hash = hashPayloadDirectory(payload_dir);
    if (payload_hash.empty()) {
        std::cerr << "error: failed to hash payload directory" << std::endl;
        return 1;
    }

    Manifest m;
    m.package_name = name;
    m.version = version;
    m.build_id = iso8601Now();
    m.payload_hash = payload_hash;
    m.sbom_hash = sbom_hash;
    m.expires_at = formatExpiry();

    std::string manifest_json = buildManifestJson(m);

    struct archive* a = archive_write_new();
    archive_write_add_filter_gzip(a);
    archive_write_set_format_pax_restricted(a);

    int r = archive_write_open_filename(a, output_path.c_str());
    if (r != ARCHIVE_OK) {
        std::cerr << "error: cannot open output file: " << output_path << std::endl;
        archive_write_free(a);
        return 1;
    }

    if (addPayloadFiles(a, payload_dir)) {
        archive_write_close(a);
        archive_write_free(a);
        fs::remove(output_path);
        return 1;
    }

    if (writeBufferToArchive(a, "metadata/manifest.json",
                                 manifest_json.data(), manifest_json.size())) {
        archive_write_close(a);
        archive_write_free(a);
        fs::remove(output_path);
        return 1;
    }

    if (writeFileToArchive(a, "metadata/sbom.spdx.json", sbom_path)) {
        archive_write_close(a);
        archive_write_free(a);
        fs::remove(output_path);
        return 1;
    }

    archive_write_close(a);
    archive_write_free(a);

    std::cout << clr::green("Package created:") << " " << clr::bold(output_path) << std::endl;
    std::cout << "  Package:      " << clr::bold(name + " " + version) << std::endl;
    std::cout << "  Payload hash: " << clr::yellow("sha256:" + payload_hash) << std::endl;
    std::cout << "  SBOM hash:    " << clr::yellow("sha256:" + sbom_hash) << std::endl;
    return 0;
}
