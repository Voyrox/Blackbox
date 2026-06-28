#pragma once
#include <string>

namespace clr {
inline std::string ok(const std::string& text) {
    return "\033[32m\u2713 " + text + "\033[0m";
}
inline std::string fail(const std::string& text) {
    return "\033[31m\u2717 " + text + "\033[0m";
}
inline std::string green(const std::string& text) {
    return "\033[32m" + text + "\033[0m";
}
inline std::string red(const std::string& text) {
    return "\033[31m" + text + "\033[0m";
}
inline std::string yellow(const std::string& text) {
    return "\033[33m" + text + "\033[0m";
}
inline std::string cyan(const std::string& text) {
    return "\033[36m" + text + "\033[0m";
}
inline std::string bold(const std::string& text) {
    return "\033[1m" + text + "\033[0m";
}
}  // namespace clr
