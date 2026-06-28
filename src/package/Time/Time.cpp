#include "package/lib.hpp"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

static std::tm gmtimePortable(const std::time_t& t) {
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    return tm;
}

std::string iso8601Now() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    auto tm = gmtimePortable(t);
    std::ostringstream out;
    out << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return out.str();
}
