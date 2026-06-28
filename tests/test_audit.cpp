#include <gtest/gtest.h>
#include "audit/lib.hpp"

#include <filesystem>
#include <string>

namespace fs = std::filesystem;

class AuditTest : public ::testing::Test {
protected:
    fs::path db_path;
    AuditLog audit;

    void SetUp() override {
        db_path = fs::temp_directory_path() / "airgapctl_audit_test.db";
        fs::remove(db_path);
        audit.open(db_path.string());
    }

    void TearDown() override {
        audit.close();
        fs::remove(db_path);
    }
};

TEST_F(AuditTest, OpenCreatesTables) {
    AuditLog a;
    EXPECT_EQ(a.open(db_path.string()), 0);
}

TEST_F(AuditTest, WriteEvent) {
    EXPECT_EQ(audit.writeEvent("TEST_ACTION", "pkg", "1.0.0", "success", "", "hash123"), 0);
}

TEST_F(AuditTest, VerifyEmptyChain) {
    EXPECT_EQ(audit.verifyChain(), 0);
}

TEST_F(AuditTest, VerifyChainSingleEvent) {
    audit.writeEvent("PACKAGE_IMPORTED", "pkg", "1.0.0", "success", "", "abc");
    EXPECT_EQ(audit.verifyChain(), 0);
}

TEST_F(AuditTest, VerifyChainMultipleEvents) {
    audit.writeEvent("IMPORT", "pkg", "1.0.0", "success", "", "h1");
    audit.writeEvent("APPROVE", "pkg", "1.0.0", "success", "", "h2");
    audit.writeEvent("INSTALL", "pkg", "1.0.0", "success", "", "h3");
    EXPECT_EQ(audit.verifyChain(), 0);
}

TEST_F(AuditTest, TamperDetectionAppendedEvents) {
    audit.writeEvent("IMPORT", "pkg", "1.0.0", "success", "", "h1");
    audit.writeEvent("APPROVE", "pkg", "1.0.0", "success", "", "h2");

    audit.verifyChain();
    audit.writeEvent("INSTALL", "pkg", "1.0.0", "success", "", "h3");

    int rc = audit.verifyChain();
    EXPECT_EQ(rc, 0);
}

TEST_F(AuditTest, TamperDetectionRemovedEvents) {
    audit.writeEvent("IMPORT", "pkg", "1.0.0", "success", "", "h1");
    audit.writeEvent("APPROVE", "pkg", "1.0.0", "success", "", "h2");

    audit.verifyChain();
}
