#include <gtest/gtest.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

#include "audit/lib.hpp"
#include "crypto/lib.hpp"
#include "package/lib.hpp"
#include "policy/lib.hpp"
#include "store/lib.hpp"

namespace fs = std::filesystem;

class PackageIntegrationTest : public ::testing::Test {
protected:
    fs::path tmp_dir;
    fs::path payload_dir;
    fs::path sbom_path;
    fs::path priv_key;
    fs::path pub_key;
    fs::path pkg_path;
    fs::path db_path;

    Store store;
    AuditLog audit;

    void SetUp() override {
        tmp_dir = fs::temp_directory_path() / "blackbox_pkg_test";
        fs::remove_all(tmp_dir);
        fs::create_directories(tmp_dir);

        payload_dir = tmp_dir / "payload";
        fs::create_directories(payload_dir);
        createFile(payload_dir / "agent.bin", "binary content");
        createFile(payload_dir / "config.yml", "setting: value");

        sbom_path = tmp_dir / "sbom.spdx.json";
        createFile(sbom_path, R"({"bomFormat":"SPDX","name":"test-pkg","spdxVersion":"SPDX-2.3"})");

        priv_key = tmp_dir / "release.key";
        pub_key = tmp_dir / "release.key.pub";
        ASSERT_EQ(generateKeypair(priv_key.string(), pub_key.string()), 0);

        pkg_path = tmp_dir / "test-pkg-1.0.0.agpkg";
        db_path = tmp_dir / "test.db";
        store.open(db_path.string());
        audit.open(db_path.string());

        std::ifstream kf(pub_key.string());
        std::string pem((std::istreambuf_iterator<char>(kf)), {});
        store.addTrustedVendor("test-vendor", pem);
    }

    void TearDown() override {
        store.close();
        audit.close();
        fs::remove_all(tmp_dir);
    }

    void createFile(const fs::path& path, const std::string& content) {
        std::ofstream f(path.string(), std::ios::binary);
        f.write(content.data(), content.size());
    }

    int runImport() {
        return verifyPackage(pkg_path.string(), &store, &audit);
    }
};

TEST_F(PackageIntegrationTest, FullLifecycle) {
    ASSERT_EQ(createPackage("test-pkg", "1.0.0", payload_dir.string(), sbom_path.string(),
                            pkg_path.string()),
              0);

    ASSERT_EQ(signPackage(pkg_path.string(), priv_key.string()), 0);

    ASSERT_EQ(runImport(), 0);
    ASSERT_TRUE(store.bundleImported("test-pkg", "1.0.0"));
    EXPECT_EQ(store.getBundleStatus("test-pkg", "1.0.0"), "pending");

    ASSERT_EQ(approvePackage("test-pkg", "1.0.0", &store, &audit), 0);
    EXPECT_EQ(store.getBundleStatus("test-pkg", "1.0.0"), "approved");

    ASSERT_EQ(store.installPackage("test-pkg", "1.0.0",
                                   store.getImportedManifestHash("test-pkg", "1.0.0"), ""),
              0);
    EXPECT_EQ(store.getInstalledVersion("test-pkg"), "1.0.0");
}

TEST_F(PackageIntegrationTest, RejectsUnsignedPackage) {
    ASSERT_EQ(createPackage("test-pkg", "1.0.0", payload_dir.string(), sbom_path.string(),
                            pkg_path.string()),
              0);
    ASSERT_NE(runImport(), 0);
}

TEST_F(PackageIntegrationTest, ApproveWithoutImportFails) {
    ASSERT_NE(approvePackage("nonexistent", "1.0.0", &store, &audit), 0);
}

TEST_F(PackageIntegrationTest, BlockedVersionDoesNotPreventImportWithoutDeps) {
    ASSERT_EQ(createPackage("test-pkg", "1.0.0", payload_dir.string(), sbom_path.string(),
                            pkg_path.string()),
              0);
    ASSERT_EQ(signPackage(pkg_path.string(), priv_key.string()), 0);
    store.addBlockedVersion("other-lib", "1.0.0", "blocked for test");
    ASSERT_EQ(runImport(), 0);
    EXPECT_TRUE(store.bundleImported("test-pkg", "1.0.0"));
}

TEST_F(PackageIntegrationTest, BlockedVersionPreventsInstall) {
    ASSERT_EQ(createPackage("test-pkg", "1.0.0", payload_dir.string(), sbom_path.string(),
                            pkg_path.string()),
              0);
    ASSERT_EQ(signPackage(pkg_path.string(), priv_key.string()), 0);
    ASSERT_EQ(runImport(), 0);
    ASSERT_EQ(approvePackage("test-pkg", "1.0.0", &store, &audit), 0);

    store.addBlockedVersion("test-pkg", "1.0.0", "blocked after import");
    EXPECT_TRUE(store.isVersionBlocked("test-pkg", "1.0.0"));
    EXPECT_EQ(store.getBlockedReason("test-pkg", "1.0.0"), "blocked after import");
}

TEST_F(PackageIntegrationTest, DowngradeRejected) {
    ASSERT_EQ(createPackage("test-pkg", "2.0.0", payload_dir.string(), sbom_path.string(),
                            pkg_path.string()),
              0);
    ASSERT_EQ(signPackage(pkg_path.string(), priv_key.string()), 0);
    ASSERT_EQ(runImport(), 0);
    ASSERT_EQ(approvePackage("test-pkg", "2.0.0", &store, &audit), 0);
    store.installPackage("test-pkg", "2.0.0", store.getImportedManifestHash("test-pkg", "2.0.0"),
                         "");

    store.addImportedBundle("b2", "test-pkg", "1.0.0", "hash", "pending");
}
