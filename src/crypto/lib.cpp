#include "lib.hpp"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

#include "color.hpp"

static std::string toHex(const unsigned char* hash, size_t len) {
    std::ostringstream out;
    for (size_t i = 0; i < len; i++)
        out << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return out.str();
}

std::string sha256File(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return {};

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);

    char buf[8192];
    while (file.read(buf, sizeof(buf)) || file.gcount()) {
        EVP_DigestUpdate(ctx, buf, file.gcount());
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx, hash, &len);
    std::string result = toHex(hash, len);
    EVP_MD_CTX_free(ctx);
    return result;
}

std::string sha256Data(const std::string& data) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    EVP_DigestFinal_ex(ctx, hash, &len);
    EVP_MD_CTX_free(ctx);

    return toHex(hash, len);
}

int generateKeypair(const std::string& priv_path, const std::string& pub_path) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!ctx) {
        std::cerr << "error: failed to create key context" << std::endl;
        return 1;
    }

    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1);

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        std::cerr << "error: key generation failed" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }
    EVP_PKEY_CTX_free(ctx);

    FILE* f = fopen(priv_path.c_str(), "wb");
    if (!f) {
        std::cerr << "error: cannot write " << priv_path << std::endl;
        EVP_PKEY_free(pkey);
        return 1;
    }
    PEM_write_PrivateKey(f, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(f);

    f = fopen(pub_path.c_str(), "wb");
    if (!f) {
        std::cerr << "error: cannot write " << pub_path << std::endl;
        EVP_PKEY_free(pkey);
        return 1;
    }
    PEM_write_PUBKEY(f, pkey);
    fclose(f);

    EVP_PKEY_free(pkey);
    std::cout << clr::green("Generated key pair:") << std::endl;
    std::cout << "  Private: " << clr::cyan(priv_path) << std::endl;
    std::cout << "  Public:  " << clr::cyan(pub_path) << std::endl;
    return 0;
}

int signFile(const std::string& file_path, const std::string& key_path,
             const std::string& sig_path) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file) {
        std::cerr << "error: cannot read " << file_path << std::endl;
        return 1;
    }

    FILE* f = fopen(key_path.c_str(), "rb");
    if (!f) {
        std::cerr << "error: cannot read " << key_path << std::endl;
        return 1;
    }
    EVP_PKEY* pkey = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
    fclose(f);
    if (!pkey) {
        std::cerr << "error: failed to load private key" << std::endl;
        return 1;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey);

    char buf[8192];
    while (file.read(buf, sizeof(buf)) || file.gcount()) {
        EVP_DigestSignUpdate(ctx, buf, file.gcount());
    }

    size_t sig_len = 0;
    EVP_DigestSignFinal(ctx, nullptr, &sig_len);
    std::vector<unsigned char> sig(sig_len);
    EVP_DigestSignFinal(ctx, sig.data(), &sig_len);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    FILE* sf = fopen(sig_path.c_str(), "wb");
    if (!sf) {
        std::cerr << "error: cannot write " << sig_path << std::endl;
        return 1;
    }
    fwrite(sig.data(), 1, sig_len, sf);
    fclose(sf);

    std::cout << clr::green("Signature:") << " " << sig_path << std::endl;
    return 0;
}

bool verifyFile(const std::string& file_path, const std::string& sig_path,
                const std::string& pub_key_path) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file) {
        std::cerr << "error: cannot read " << file_path << std::endl;
        return false;
    }

    FILE* f = fopen(pub_key_path.c_str(), "rb");
    if (!f) {
        std::cerr << "error: cannot read " << pub_key_path << std::endl;
        return false;
    }
    EVP_PKEY* pkey = PEM_read_PUBKEY(f, nullptr, nullptr, nullptr);
    fclose(f);
    if (!pkey) {
        std::cerr << "error: failed to load public key" << std::endl;
        return false;
    }

    FILE* sf = fopen(sig_path.c_str(), "rb");
    if (!sf) {
        std::cerr << "error: cannot read " << sig_path << std::endl;
        EVP_PKEY_free(pkey);
        return false;
    }
    fseek(sf, 0, SEEK_END);
    long sig_len = ftell(sf);
    fseek(sf, 0, SEEK_SET);
    std::vector<unsigned char> sig(sig_len);
    fread(sig.data(), 1, sig_len, sf);
    fclose(sf);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey);

    file.clear();
    file.seekg(0);
    char buf[8192];
    while (file.read(buf, sizeof(buf)) || file.gcount()) {
        EVP_DigestVerifyUpdate(ctx, buf, file.gcount());
    }

    int ret = EVP_DigestVerifyFinal(ctx, sig.data(), sig_len);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return ret == 1;
}

bool verifyFileWithKey(const std::string& file_path, const std::string& sig_path,
                       const std::string& pub_key_pem) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file) return false;

    BIO* bio = BIO_new_mem_buf(pub_key_pem.data(), pub_key_pem.size());
    if (!bio) return false;
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) return false;

    FILE* sf = fopen(sig_path.c_str(), "rb");
    if (!sf) {
        EVP_PKEY_free(pkey);
        return false;
    }
    fseek(sf, 0, SEEK_END);
    long sig_len = ftell(sf);
    fseek(sf, 0, SEEK_SET);
    std::vector<unsigned char> sig(sig_len);
    fread(sig.data(), 1, sig_len, sf);
    fclose(sf);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey);

    file.clear();
    file.seekg(0);
    char buf[8192];
    while (file.read(buf, sizeof(buf)) || file.gcount())
        EVP_DigestVerifyUpdate(ctx, buf, file.gcount());

    int ret = EVP_DigestVerifyFinal(ctx, sig.data(), sig_len);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return ret == 1;
}
