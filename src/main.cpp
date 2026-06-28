#include "package/lib.hpp"
#include "color.hpp"
#include "crypto/lib.hpp"
#include "store/lib.hpp"
#include "audit/lib.hpp"
#include "policy/lib.hpp"

#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

static void printUsage() {
    std::cout << "\n";
    std::cout << clr::bold("blackbox") << "  — Secure update manager for air-gapped systems\n";
    std::cout << "\n";
    std::cout << clr::bold("Usage:") << "  blackbox " << clr::cyan("<command>") << " " << clr::yellow("[options]") << "\n";
    std::cout << "\n";
    std::cout << "  " << clr::bold("Key management") << "\n";
    std::cout << "    " << clr::cyan("keygen") << " --out " << clr::yellow("<dir>") << R"(                                   Generate ECDSA P-256 key pair)" << "\n";
    std::cout << "\n";
    std::cout << "  " << clr::bold("Package operations") << "\n";
    std::cout << "    " << clr::cyan("package create") << " --name " << clr::yellow("<name>") << " --version " << clr::yellow("<ver>") << "\n";
    std::cout << "        --payload " << clr::yellow("<path>") << " --sbom " << clr::yellow("<path>") << " --out " << clr::yellow("<output>") << "    Create a signed package bundle\n";
    std::cout << "    " << clr::cyan("package sign") << " " << clr::yellow("<pkg>") << " --key " << clr::yellow("<private_key>") << "               Sign an existing package\n";
    std::cout << "\n";
    std::cout << "  " << clr::bold("Trust management") << "\n";
    std::cout << "    " << clr::cyan("trust add") << " " << clr::yellow("<pub_key>") << " --name " << clr::yellow("<vendor>") << "                  Add a trusted vendor public key\n";
    std::cout << "    " << clr::cyan("trust list") << R"(                                           List trusted vendors)" << "\n";
    std::cout << "    " << clr::cyan("trust remove") << " --name " << clr::yellow("<vendor>") << R"(                         Remove a trusted vendor)" << "\n";
    std::cout << "\n";
    std::cout << "  " << clr::bold("Import / Approve / Install") << "\n";
    std::cout << "    " << clr::cyan("import") << " " << clr::yellow("<pkg>") << R"(                                         Verify and import a package)" << "\n";
    std::cout << "    " << clr::cyan("approve") << " " << clr::yellow("<name>") << " --version " << clr::yellow("<ver>") << R"(                       Approve a pending bundle for install)" << "\n";
    std::cout << "    " << clr::cyan("install") << " " << clr::yellow("<name>") << " --version " << clr::yellow("<ver>") << R"(                       Install an approved bundle)" << "\n";
    std::cout << "\n";
    std::cout << "  " << clr::bold("Policy (dependency blocking)") << "\n";
    std::cout << "    " << clr::cyan("policy block") << " " << clr::yellow("<name>") << " " << clr::yellow("<version>") << " --reason " << clr::yellow("<text>") << "        Block a vulnerable dependency\n";
    std::cout << "    " << clr::cyan("policy unblock") << " " << clr::yellow("<name>") << " " << clr::yellow("<version>") << R"(                      Unblock a dependency)" << "\n";
    std::cout << "    " << clr::cyan("policy list") << R"(                                          List blocked versions)" << "\n";
    std::cout << "\n";
    std::cout << "  " << clr::bold("Status & Audit") << "\n";
    std::cout << "    " << clr::cyan("status") << R"(                                               Show installed packages and imported bundles)" << "\n";
    std::cout << "    " << clr::cyan("audit verify-chain") << R"(                                   Verify tamper-evident audit chain)" << "\n";
    std::cout << "\n";
}

static const char* getArg(int& i, int argc, char* argv[], const char* flag) {
    if (i + 1 >= argc) {
        std::cerr << clr::red("error:") << " " << flag << " requires a value" << std::endl;
        return nullptr;
    }
    return argv[++i];
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage();
        return 1;
    }

    if (std::strcmp(argv[1], "keygen") == 0) {
        std::string out_dir = "keys";
        for (int i = 2; i < argc; i++) {
            if (std::strcmp(argv[i], "--out") == 0) {
                auto v = getArg(i, argc, argv, "--out");
                if (!v) return 1;
                out_dir = v;
            } else {
                std::cerr << clr::red("error:") << " unknown flag: " << argv[i] << std::endl;
                return 1;
            }
        }
        std::string priv = out_dir + "/release.key";
        std::string pub = out_dir + "/release.key.pub";
        return generateKeypair(priv, pub);
    }

    if (std::strcmp(argv[1], "package") == 0 && argc >= 3) {

        if (std::strcmp(argv[2], "create") == 0) {
            std::string name, version, payload, sbom, out;
            for (int i = 3; i < argc; i++) {
                if (std::strcmp(argv[i], "--name") == 0) {
                    auto v = getArg(i, argc, argv, "--name");
                    if (!v) return 1; name = v;
                } else if (std::strcmp(argv[i], "--version") == 0) {
                    auto v = getArg(i, argc, argv, "--version");
                    if (!v) return 1; version = v;
                } else if (std::strcmp(argv[i], "--payload") == 0) {
                    auto v = getArg(i, argc, argv, "--payload");
                    if (!v) return 1; payload = v;
                } else if (std::strcmp(argv[i], "--sbom") == 0) {
                    auto v = getArg(i, argc, argv, "--sbom");
                    if (!v) return 1; sbom = v;
                } else if (std::strcmp(argv[i], "--out") == 0) {
                    auto v = getArg(i, argc, argv, "--out");
                    if (!v) return 1; out = v;
                } else {
                    std::cerr << clr::red("error:") << " unknown flag: " << argv[i] << std::endl;
                    return 1;
                }
            }
            if (name.empty() || version.empty() || payload.empty() || sbom.empty() || out.empty()) {
                std::cerr << clr::red("error:") << " missing required arguments" << std::endl;
                printUsage();
                return 1;
            }
            return createPackage(name, version, payload, sbom, out);
        }

        if (std::strcmp(argv[2], "sign") == 0) {
            if (argc < 4) {
            std::cerr << clr::red("error:") << " missing package path" << std::endl;
                return 1;
            }
            std::string pkg_path = argv[3];
            std::string key_path = "keys/release.key";
            for (int i = 4; i < argc; i++) {
                if (std::strcmp(argv[i], "--key") == 0) {
                    auto v = getArg(i, argc, argv, "--key");
                    if (!v) return 1; key_path = v;
                } else {
                    std::cerr << clr::red("error:") << " unknown flag: " << argv[i] << std::endl;
                    return 1;
                }
            }
            return signPackage(pkg_path, key_path);
        }

        std::cerr << clr::red("error:") << " unknown package subcommand: " << argv[2] << std::endl;
        return 1;
    }

    if (std::strcmp(argv[1], "import") == 0) {
        if (argc < 3) {
            std::cerr << clr::red("error:") << " missing package path" << std::endl;
            return 1;
        }
        std::string pkg_path = argv[2];

        Store store;
        store.open("airgap.db");
        AuditLog audit;
        audit.open("airgap.db");
        return verifyPackage(pkg_path, &store, &audit);
    }

    if (std::strcmp(argv[1], "trust") == 0 && argc >= 3) {
        Store store;
        store.open("airgap.db");

        if (std::strcmp(argv[2], "add") == 0) {
            if (argc < 4) {
                std::cerr << clr::red("error:") << " usage: blackbox trust add <pub_key> --name <vendor>" << std::endl;
                return 1;
            }
            std::string key_path = argv[3];
            std::string name;
            for (int i = 4; i < argc; i++) {
                if (std::strcmp(argv[i], "--name") == 0) {
                    auto v = getArg(i, argc, argv, "--name");
                    if (!v) return 1; name = v;
                } else {
                    std::cerr << clr::red("error:") << " unknown flag: " << argv[i] << std::endl;
                    return 1;
                }
            }
            if (name.empty()) {
                std::cerr << clr::red("error:") << " --name is required" << std::endl;
                return 1;
            }
            std::ifstream f(key_path);
            if (!f) {
                std::cerr << clr::red("error:") << " cannot read " << key_path << std::endl;
                return 1;
            }
            std::string pem((std::istreambuf_iterator<char>(f)), {});
            if (store.addTrustedVendor(name, pem) != 0) {
                std::cerr << "error: failed to add trusted vendor" << std::endl;
                return 1;
            }
            std::string fp = sha256Data(pem);
            std::cout << clr::green("Trusted vendor added:") << " " << clr::bold(name) << std::endl;
            std::cout << "  Fingerprint: " << fp << std::endl;
            std::cout << "  (verify this fingerprint with the vendor out-of-band)" << std::endl;
            return 0;
        }

        if (std::strcmp(argv[2], "remove") == 0) {
            std::string name;
            for (int i = 3; i < argc; i++) {
                if (std::strcmp(argv[i], "--name") == 0) {
                    auto v = getArg(i, argc, argv, "--name");
                    if (!v) return 1; name = v;
                } else {
                    std::cerr << clr::red("error:") << " unknown flag: " << argv[i] << std::endl;
                    return 1;
                }
            }
            if (name.empty()) {
                std::cerr << clr::red("error:") << " --name is required" << std::endl;
                return 1;
            }
            if (store.removeTrustedVendor(name) != 0) {
                std::cerr << "error: failed to remove trusted vendor" << std::endl;
                return 1;
            }
            std::cout << clr::green("Trusted vendor removed:") << " " << clr::bold(name) << std::endl;
            return 0;
        }

        if (std::strcmp(argv[2], "list") == 0) {
            auto vendors = store.listTrustedVendors();
            std::cout << clr::bold("Trusted vendors:") << std::endl;
            if (vendors.empty()) {
                std::cout << "  (none)" << std::endl;
            } else {
                for (const auto& v : vendors) {
                    std::cout << "  " << clr::bold(v.name) << std::endl;
                    std::cout << "    Fingerprint: " << v.fingerprint << std::endl;
                    std::cout << "    Added:       " << v.added_at << std::endl;
                }
            }
            return 0;
        }

        std::cerr << clr::red("error:") << " unknown trust subcommand: " << argv[2] << std::endl;
        return 1;
    }

    if (std::strcmp(argv[1], "install") == 0) {
        if (argc < 4) {
            std::cerr << clr::red("error:") << " usage: blackbox install <name> --version <ver>" << std::endl;
            return 1;
        }
        std::string name = argv[2];
        std::string version;
        for (int i = 3; i < argc; i++) {
            if (std::strcmp(argv[i], "--version") == 0) {
                auto v = getArg(i, argc, argv, "--version");
                if (!v) return 1; version = v;
                } else {
                    std::cerr << clr::red("error:") << " unknown flag: " << argv[i] << std::endl;
                    return 1;
                }
            }
            if (version.empty()) {
            std::cerr << clr::red("error:") << " --version is required" << std::endl;
            return 1;
        }

        Store store;
        AuditLog audit;
        store.open("airgap.db");
        audit.open("airgap.db");
        store.beginTransaction();

        if (!store.bundleImported(name, version)) {
            std::string reason = "bundle not imported";
            std::cerr << clr::red("error:") << " " << name << " " << version
                      << " has not been imported. Run 'blackbox import' first." << std::endl;
            store.rollbackTransaction();
            audit.writeEvent("PACKAGE_IMPORTED", name, version, "failed", reason, "");
            return 1;
        }

        std::string status = store.getBundleStatus(name, version);
        if (status != "approved") {
            std::string reason = "not approved";
            std::cerr << clr::red("error:") << " " << name << " " << version
                      << " has status '" << status << "'. Run 'blackbox approve' first." << std::endl;
            store.rollbackTransaction();
            audit.writeEvent("PACKAGE_INSTALL_REJECTED", name, version, "failed", reason, "");
            return 1;
        }

        std::string installed = store.getInstalledVersion(name);
        if (!installed.empty() && versionLessThan(version, installed)) {
            std::string reason = "version " + version + " is older than installed " + installed;
            std::cout << clr::fail("Install rejected: downgrade detected") << std::endl;
            std::cout << "  " << name << " " << version
                      << " is older than installed version " << installed << std::endl;
            store.rollbackTransaction();
            audit.writeEvent("ROLLBACK_BLOCKED", name, version, "failed", reason, "");
            return 1;
        }

        std::string manifest_hash = store.getImportedManifestHash(name, version);
        store.installPackage(name, version, manifest_hash, installed);
        store.commitTransaction();

        std::cout << clr::green("Installed:") << " " << clr::bold(name + " " + version) << std::endl;
        if (!installed.empty()) {
            std::cout << "  Previous version: " << installed << std::endl;
        }
        audit.writeEvent("PACKAGE_INSTALLED", name, version, "success", "", manifest_hash);
        return 0;
    }

    if (std::strcmp(argv[1], "approve") == 0) {
        if (argc < 4) {
            std::cerr << clr::red("error:") << " usage: blackbox approve <name> --version <ver>" << std::endl;
            return 1;
        }
        std::string name = argv[2];
        std::string version;
        for (int i = 3; i < argc; i++) {
            if (std::strcmp(argv[i], "--version") == 0) {
                auto v = getArg(i, argc, argv, "--version");
                if (!v) return 1; version = v;
            } else {
                std::cerr << clr::red("error:") << " unknown flag: " << argv[i] << std::endl;
                return 1;
            }
        }
        if (version.empty()) {
            std::cerr << clr::red("error:") << " --version is required" << std::endl;
            return 1;
        }

        Store store;
        AuditLog audit;
        store.open("airgap.db");
        audit.open("airgap.db");
        return approvePackage(name, version, &store, &audit);
    }

    if (std::strcmp(argv[1], "policy") == 0 && argc >= 3) {
        Store store;
        store.open("airgap.db");

        if (std::strcmp(argv[2], "block") == 0) {
            if (argc < 5) {
                std::cerr << clr::red("error:") << " usage: blackbox policy block <name> <version> --reason <text>" << std::endl;
                return 1;
            }
            std::string pkg = argv[3];
            std::string ver = argv[4];
            std::string reason = "blocked by policy";
            for (int i = 5; i < argc; i++) {
                if (std::strcmp(argv[i], "--reason") == 0) {
                    auto v = getArg(i, argc, argv, "--reason");
                    if (!v) return 1; reason = v;
                } else {
                    std::cerr << clr::red("error:") << " unknown flag: " << argv[i] << std::endl;
                    return 1;
                }
            }
            if (store.addBlockedVersion(pkg, ver, reason) != 0) {
                std::cerr << "error: failed to block " << pkg << " " << ver << std::endl;
                return 1;
            }
            std::cout << clr::green("Blocked:") << " " << clr::bold(pkg + " " + ver) << std::endl;
            std::cout << "  Reason: " << reason << std::endl;
            return 0;
        }

        if (std::strcmp(argv[2], "unblock") == 0) {
            if (argc < 5) {
                std::cerr << clr::red("error:") << " usage: blackbox policy unblock <name> <version>" << std::endl;
                return 1;
            }
            std::string pkg = argv[3];
            std::string ver = argv[4];
            if (store.removeBlockedVersion(pkg, ver) != 0) {
                std::cerr << "error: failed to unblock " << pkg << " " << ver << std::endl;
                return 1;
            }
            std::cout << clr::green("Unblocked:") << " " << clr::bold(pkg + " " + ver) << std::endl;
            return 0;
        }

        if (std::strcmp(argv[2], "list") == 0) {
            auto blocked = store.listBlockedVersions();
            std::cout << clr::bold("Blocked versions:") << std::endl;
            if (blocked.empty()) {
                std::cout << "  (none)" << std::endl;
            } else {
                for (const auto& [pkg, ver, reason] : blocked) {
                    std::cout << "  " << pkg << " " << ver << "  (" << reason << ")" << std::endl;
                }
            }
            return 0;
        }

        std::cerr << clr::red("error:") << " unknown policy subcommand: " << argv[2] << std::endl;
        return 1;
    }

    if (std::strcmp(argv[1], "status") == 0) {
        Store store;
        if (store.open("airgap.db") != 0) {
            std::cerr << clr::red("no store found") << std::endl;
            return 1;
        }

        auto installed = store.getAllInstalled();
        auto imported = store.getAllImported();

        std::cout << clr::bold("Installed packages:") << std::endl;
        if (installed.empty()) {
            std::cout << "  (none)" << std::endl;
        } else {
            for (const auto& [pkg, ver, prev, at] : installed) {
                std::cout << "  " << pkg << " " << ver
                          << " (installed " << at << ")";
                if (!prev.empty()) std::cout << " [upgraded from " << prev << "]";
                std::cout << std::endl;
            }
        }

        std::cout << std::endl << clr::bold("Imported bundles:") << std::endl;
        if (imported.empty()) {
            std::cout << "  (none)" << std::endl;
        } else {
            for (const auto& [pkg, ver, st, at] : imported) {
                std::cout << "  " << pkg << " " << ver
                          << " [" << st << "] (imported " << at << ")" << std::endl;
            }
        }
        return 0;
    }

    if (std::strcmp(argv[1], "audit") == 0 && argc >= 3 &&
        std::strcmp(argv[2], "verify-chain") == 0) {
        AuditLog audit;
        if (audit.open("airgap.db") != 0) {
            std::cerr << clr::red("no audit log found") << std::endl;
            return 1;
        }
        audit.writeEvent("AUDIT_CHAIN_VERIFIED", "", "", "success", "", "");
        return audit.verifyChain();
    }

    std::cerr << clr::red("error:") << " unknown command: " << argv[1] << std::endl;
    printUsage();
    return 1;
}
