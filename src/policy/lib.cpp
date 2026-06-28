#include "lib.hpp"
#include "store/lib.hpp"

std::vector<DepCheck> checkDependencies(const std::vector<std::pair<std::string, std::string>>& deps, Store* store) {
    std::vector<DepCheck> results;
    if (!store) return results;

    for (const auto& [name, version] : deps) {
        DepCheck dc;
        dc.name = name;
        dc.version = version;
        dc.blocked = store->isVersionBlocked(name, version);
        if (dc.blocked)
            dc.reason = store->getBlockedReason(name, version);
        results.push_back(dc);
    }
    return results;
}
