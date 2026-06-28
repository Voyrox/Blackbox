#include <gtest/gtest.h>
#include "crypto/lib.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>

namespace fs = std::filesystem;

class CryptoTest : public ::testing::Test {
protected:
    fs::path tmp_dir;

    void SetUp() override {
        tmp_dir = fs::temp_directory_path() / "blackbox_crypto_test";
        fs::create_directories(tmp_dir);
    }

    void TearDown() override {
        fs::remove_all(tmp_dir);
    }

    std::string makeFile(const std::string& name, const std::string& content) {
        auto path = tmp_dir / name;
        std::ofstream f(path.string(), std::ios::binary);
        f.write(content.data(), content.size());
        return path.string();
    }
};

TEST_F(CryptoTest, Sha256DataKnownValues) {
    EXPECT_EQ(sha256Data(""),
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    EXPECT_EQ(sha256Data("hello"),
              "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
}

TEST_F(CryptoTest, Sha256DataConsistency) {
    std::string data = "the quick brown fox jumps over the lazy dog";
    std::string h1 = sha256Data(data);
    std::string h2 = sha256Data(data);
    EXPECT_EQ(h1, h2);
}

TEST_F(CryptoTest, Sha256File) {
    auto path = makeFile("test.bin", "file content");
    std::string h = sha256File(path);
    EXPECT_FALSE(h.empty());
    EXPECT_EQ(h, sha256Data("file content"));
}

TEST_F(CryptoTest, Sha256FileNotFound) {
    EXPECT_TRUE(sha256File("/nonexistent/file.bin").empty());
}

TEST_F(CryptoTest, KeygenSignVerify) {
    std::string priv = (tmp_dir / "test.key").string();
    std::string pub = (tmp_dir / "test.key.pub").string();
    ASSERT_EQ(generateKeypair(priv, pub), 0);

    auto data_path = makeFile("data.bin", "sign me");
    std::string sig = data_path + ".sig";
    ASSERT_EQ(signFile(data_path, priv, sig), 0);

    EXPECT_TRUE(verifyFile(data_path, sig, pub));
    EXPECT_FALSE(verifyFile(data_path, sig + ".nonexistent", pub));
}

TEST_F(CryptoTest, VerifyTamperedFile) {
    std::string priv = (tmp_dir / "tamper.key").string();
    std::string pub = (tmp_dir / "tamper.key.pub").string();
    ASSERT_EQ(generateKeypair(priv, pub), 0);

    auto data_path = makeFile("original.bin", "original content");
    std::string sig = data_path + ".sig";
    ASSERT_EQ(signFile(data_path, priv, sig), 0);

    makeFile("original.bin", "tampered content");
    EXPECT_FALSE(verifyFile(data_path, sig, pub));
}
