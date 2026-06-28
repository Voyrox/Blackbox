#include "package/lib.hpp"

#include <sstream>

bool versionLessThan(const std::string& a, const std::string& b) {
    std::istringstream sa(a), sb(b);
    int majorA = 0, majorB = 0, minorA = 0, minorB = 0, patchA = 0, patchB = 0;
    char dot;
    sa >> majorA >> dot >> minorA >> dot >> patchA;
    sb >> majorB >> dot >> minorB >> dot >> patchB;
    if (majorA != majorB) return majorA < majorB;
    if (minorA != minorB) return minorA < minorB;
    return patchA < patchB;
}
