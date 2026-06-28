#include "package/lib.hpp"
#include "color.hpp"
#include "store/lib.hpp"
#include "audit/lib.hpp"

#include <iostream>

int approvePackage(const std::string& pkg_name, const std::string& version,
                    Store* store, AuditLog* audit) {
    if (!store) {
        std::cerr << clr::red("error:") << " no store" << std::endl;
        return 1;
    }

    if (!store->bundleImported(pkg_name, version)) {
        std::cerr << clr::red("error:") << " " << pkg_name << " " << version
                  << " has not been imported. Run 'airgapctl import' first." << std::endl;
        return 1;
    }

    std::string cur_status = store->getBundleStatus(pkg_name, version);
    if (cur_status != "pending") {
        if (cur_status == "approved") {
            std::cout << clr::yellow(pkg_name + " " + version + " is already approved") << std::endl;
            return 0;
        }
        std::cerr << clr::red("error:") << " unexpected status: " << cur_status << std::endl;
        return 1;
    }

    store->setBundleStatus(pkg_name, version, "approved");
    std::cout << clr::green("Approved:") << " " << clr::bold(pkg_name + " " + version) << std::endl;

    if (audit)
        audit->writeEvent("PACKAGE_APPROVED", pkg_name, version, "success", "", "");

    return 0;
}
