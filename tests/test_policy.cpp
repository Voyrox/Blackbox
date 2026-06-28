#include <gtest/gtest.h>
#include "policy/lib.hpp"
#include "store/lib.hpp"

#include <filesystem>

namespace fs = std::filesystem;

class PolicyTest : public ::testing::Test {
protected:
    fs::path db_path;
    Store store;

    void SetUp() override {
        db_path = fs::temp_directory_path() / "airgapctl_policy_test.db";
        fs::remove(db_path);
        store.open(db_path.string());
    }

    void TearDown() override {
        store.close();
        fs::remove(db_path);
    }
};

TEST_F(PolicyTest, NoDependenciesReturnsEmpty) {
    auto result = checkDependencies({}, &store);
    EXPECT_TRUE(result.empty());
}

TEST_F(PolicyTest, AllDepsAllowed) {
    store.addImportedBundle("b1", "libfoo", "1.0.0", "hash", "approved");
    store.addImportedBundle("b2", "libbar", "1.0.0", "hash", "approved");

    std::vector<std::pair<std::string, std::string>> deps = {
        {"libfoo", "1.0.0"},
        {"libbar", "1.0.0"}
    };
    auto result = checkDependencies(deps, &store);
    ASSERT_EQ(result.size(), 2);
    EXPECT_FALSE(result[0].blocked);
    EXPECT_FALSE(result[1].blocked);
}

TEST_F(PolicyTest, BlockedDepDetected) {
    store.addBlockedVersion("evil-lib", "1.0.0", "contains malware");

    std::vector<std::pair<std::string, std::string>> deps = {
        {"good-lib", "1.0.0"},
        {"evil-lib", "1.0.0"}
    };
    auto result = checkDependencies(deps, &store);
    ASSERT_EQ(result.size(), 2);
    EXPECT_FALSE(result[0].blocked);
    EXPECT_TRUE(result[1].blocked);
    EXPECT_EQ(result[1].reason, "contains malware");
}

TEST_F(PolicyTest, NullStoreReturnsEmpty) {
    std::vector<std::pair<std::string, std::string>> deps = {{"lib", "1.0.0"}};
    auto result = checkDependencies(deps, nullptr);
    EXPECT_TRUE(result.empty());
}

TEST_F(PolicyTest, BlockedVersionDifferentVersionNotAffected) {
    store.addBlockedVersion("lib", "2.0.0", "bad");

    std::vector<std::pair<std::string, std::string>> deps = {{"lib", "1.0.0"}};
    auto result = checkDependencies(deps, &store);
    ASSERT_EQ(result.size(), 1);
    EXPECT_FALSE(result[0].blocked);
}
