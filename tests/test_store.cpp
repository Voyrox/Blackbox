#include <gtest/gtest.h>
#include "store/lib.hpp"

#include <filesystem>
#include <string>

namespace fs = std::filesystem;

class StoreTest : public ::testing::Test {
protected:
    fs::path db_path;
    Store store;

    void SetUp() override {
        db_path = fs::temp_directory_path() / "blackbox_store_test.db";
        fs::remove(db_path);
        store.open(db_path.string());
    }

    void TearDown() override {
        store.close();
        fs::remove(db_path);
    }
};

TEST_F(StoreTest, OpenCreatesTables) {
    Store s;
    EXPECT_EQ(s.open(db_path.string()), 0);
}

TEST_F(StoreTest, AddAndCheckImportedBundle) {
    ASSERT_EQ(store.addImportedBundle("bundle1", "pkgA", "1.0.0", "abc123", "pending"), 0);
    EXPECT_TRUE(store.bundleImported("pkgA", "1.0.0"));
    EXPECT_FALSE(store.bundleImported("pkgA", "2.0.0"));
    EXPECT_FALSE(store.bundleImported("pkgB", "1.0.0"));
}

TEST_F(StoreTest, GetImportedManifestHash) {
    store.addImportedBundle("b1", "pkg", "1.0.0", "hash_xyz", "pending");
    EXPECT_EQ(store.getImportedManifestHash("pkg", "1.0.0"), "hash_xyz");
    EXPECT_TRUE(store.getImportedManifestHash("nonexistent", "1.0.0").empty());
}

TEST_F(StoreTest, SetAndGetBundleStatus) {
    store.addImportedBundle("b1", "pkg", "1.0.0", "hash", "pending");
    EXPECT_EQ(store.getBundleStatus("pkg", "1.0.0"), "pending");

    store.setBundleStatus("pkg", "1.0.0", "approved");
    EXPECT_EQ(store.getBundleStatus("pkg", "1.0.0"), "approved");
}

TEST_F(StoreTest, InstallAndGetVersion) {
    store.addImportedBundle("b1", "pkg", "1.0.0", "hash", "approved");
    ASSERT_EQ(store.installPackage("pkg", "1.0.0", "hash", ""), 0);
    EXPECT_EQ(store.getInstalledVersion("pkg"), "1.0.0");
}

TEST_F(StoreTest, InstallUpgradePreservesPrevious) {
    store.addImportedBundle("b1", "pkg", "1.0.0", "hash", "approved");
    store.installPackage("pkg", "1.0.0", "hash", "");
    store.addImportedBundle("b2", "pkg", "2.0.0", "hash2", "approved");
    store.installPackage("pkg", "2.0.0", "hash2", "1.0.0");

    auto all = store.getAllInstalled();
    ASSERT_EQ(all.size(), 1);
    EXPECT_EQ(std::get<0>(all[0]), "pkg");
    EXPECT_EQ(std::get<1>(all[0]), "2.0.0");
    EXPECT_EQ(std::get<2>(all[0]), "1.0.0");
}

TEST_F(StoreTest, GetAllImported) {
    store.addImportedBundle("b1", "pkgA", "1.0.0", "h1", "pending");
    store.addImportedBundle("b2", "pkgB", "2.0.0", "h2", "approved");

    auto all = store.getAllImported();
    ASSERT_EQ(all.size(), 2);
}

TEST_F(StoreTest, IsVersionBlockedInitially) {
    EXPECT_FALSE(store.isVersionBlocked("pkg", "1.0.0"));
}

TEST_F(StoreTest, BlockAndUnblockVersion) {
    ASSERT_EQ(store.addBlockedVersion("pkg", "1.0.0", "CVE-2024-test"), 0);
    EXPECT_TRUE(store.isVersionBlocked("pkg", "1.0.0"));
    EXPECT_FALSE(store.isVersionBlocked("pkg", "1.0.1"));
    EXPECT_FALSE(store.isVersionBlocked("other", "1.0.0"));

    EXPECT_EQ(store.getBlockedReason("pkg", "1.0.0"), "CVE-2024-test");

    ASSERT_EQ(store.removeBlockedVersion("pkg", "1.0.0"), 0);
    EXPECT_FALSE(store.isVersionBlocked("pkg", "1.0.0"));
}

TEST_F(StoreTest, ListBlockedVersions) {
    store.addBlockedVersion("pkgA", "1.0.0", "bad");
    store.addBlockedVersion("pkgB", "2.0.0", "worse");

    auto list = store.listBlockedVersions();
    ASSERT_EQ(list.size(), 2);
    EXPECT_EQ(std::get<0>(list[0]), "pkgA");
    EXPECT_EQ(std::get<0>(list[1]), "pkgB");
}

TEST_F(StoreTest, RollbackTransactionOnFailure) {
    store.beginTransaction();
    store.addImportedBundle("b1", "pkg", "1.0.0", "hash", "pending");
    store.rollbackTransaction();

    EXPECT_FALSE(store.bundleImported("pkg", "1.0.0"));
}

TEST_F(StoreTest, CommitTransactionPersists) {
    store.beginTransaction();
    store.addImportedBundle("b1", "pkg", "1.0.0", "hash", "pending");
    store.commitTransaction();

    EXPECT_TRUE(store.bundleImported("pkg", "1.0.0"));
}

TEST_F(StoreTest, AddAndListTrustedVendor) {
    std::string pem = "-----BEGIN PUBLIC KEY-----\nZmFrZQ==\n-----END PUBLIC KEY-----";
    ASSERT_EQ(store.addTrustedVendor("Acme Corp", pem), 0);

    auto vendors = store.listTrustedVendors();
    ASSERT_EQ(vendors.size(), 1);
    EXPECT_EQ(vendors[0].name, "Acme Corp");
    EXPECT_EQ(vendors[0].public_key_pem, pem);
}

TEST_F(StoreTest, ListTrustedVendorsEmpty) {
    auto vendors = store.listTrustedVendors();
    EXPECT_TRUE(vendors.empty());
}

TEST_F(StoreTest, RemoveTrustedVendor) {
    std::string pem = "-----BEGIN PUBLIC KEY-----\nZmFrZQ==\n-----END PUBLIC KEY-----";
    store.addTrustedVendor("Acme Corp", pem);
    ASSERT_EQ(store.removeTrustedVendor("Acme Corp"), 0);
    EXPECT_TRUE(store.listTrustedVendors().empty());
}

TEST_F(StoreTest, GetAllVendorKeysReturnsNameAndPem) {
    std::string pem = "-----BEGIN PUBLIC KEY-----\nZmFrZQ==\n-----END PUBLIC KEY-----";
    store.addTrustedVendor("Vendor A", pem);
    store.addTrustedVendor("Vendor B", pem);

    auto keys = store.getAllVendorKeys();
    ASSERT_EQ(keys.size(), 2);
    EXPECT_EQ(keys[0].first, "Vendor A");
    EXPECT_EQ(keys[0].second, pem);
    EXPECT_EQ(keys[1].first, "Vendor B");
}

TEST_F(StoreTest, AddTrustedVendorComputesFingerprint) {
    std::string pem = "test-public-key-data";
    store.addTrustedVendor("Test Vendor", pem);

    auto vendors = store.listTrustedVendors();
    ASSERT_EQ(vendors.size(), 1);
    EXPECT_FALSE(vendors[0].fingerprint.empty());
    EXPECT_EQ(vendors[0].fingerprint.size(), 64);
}
