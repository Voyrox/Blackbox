#include "package/lib.hpp"
#include "crypto/lib.hpp"

int signPackage(const std::string& pkg_path, const std::string& key_path) {
    std::string sig_path = pkg_path + ".sig";
    return signFile(pkg_path, key_path, sig_path);
}
