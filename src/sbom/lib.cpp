#include "lib.hpp"

#include <fstream>
#include <sstream>

std::string readSbom(const std::string& path) {
    std::ifstream file(path);
    if (!file) return {};
    std::ostringstream buf;
    buf << file.rdbuf();
    return buf.str();
}
