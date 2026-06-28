#pragma once

#include <string>
#include <utility>
#include <vector>

class Store;

struct DepCheck {
    std::string name;
    std::string version;
    bool blocked;
    std::string reason;
};

std::vector<DepCheck> checkDependencies(
    const std::vector<std::pair<std::string, std::string>>& deps, Store* store);
