#include <gtest/gtest.h>
#include "package/lib.hpp"

TEST(VersionTest, EqualVersions) {
    EXPECT_FALSE(versionLessThan("1.0.0", "1.0.0"));
    EXPECT_FALSE(versionLessThan("0.0.0", "0.0.0"));
    EXPECT_FALSE(versionLessThan("99.99.99", "99.99.99"));
}

TEST(VersionTest, MajorVersionComparison) {
    EXPECT_TRUE(versionLessThan("1.0.0", "2.0.0"));
    EXPECT_FALSE(versionLessThan("2.0.0", "1.0.0"));
    EXPECT_TRUE(versionLessThan("0.9.9", "1.0.0"));
}

TEST(VersionTest, MinorVersionComparison) {
    EXPECT_TRUE(versionLessThan("1.0.0", "1.1.0"));
    EXPECT_FALSE(versionLessThan("1.1.0", "1.0.0"));
    EXPECT_TRUE(versionLessThan("1.0.9", "1.1.0"));
}

TEST(VersionTest, PatchVersionComparison) {
    EXPECT_TRUE(versionLessThan("1.0.0", "1.0.1"));
    EXPECT_FALSE(versionLessThan("1.0.1", "1.0.0"));
    EXPECT_TRUE(versionLessThan("1.0.0", "1.0.10"));
}

TEST(VersionTest, MultiDigitVersions) {
    EXPECT_TRUE(versionLessThan("10.0.0", "11.0.0"));
    EXPECT_TRUE(versionLessThan("1.20.0", "1.21.0"));
    EXPECT_TRUE(versionLessThan("1.0.99", "1.0.100"));
}

TEST(VersionTest, EmptyVersion) {
    EXPECT_TRUE(versionLessThan("", "1.0.0"));
    EXPECT_FALSE(versionLessThan("1.0.0", ""));
}

TEST(Iso8601Test, ReturnsValidFormat) {
    std::string now = iso8601Now();
    EXPECT_EQ(now.size(), 20);
    EXPECT_EQ(now[10], 'T');
    EXPECT_EQ(now[19], 'Z');
}
