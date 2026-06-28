#include "package/lib.hpp"
#include "color.hpp"
#include "crypto/lib.hpp"
#include "store/lib.hpp"
#include "audit/lib.hpp"

#include <cstring>
#include <iostream>
#include <string>

static void printUsage() {
    std::cout << clr::bold("Usage:") << "\n";
    std::cout << "  airgapctl package create --name <name> --version <ver>\n";
    std::cout << "      --payload <path> --sbom <path> --out <output>\n";
    std::cout << "  airgapctl package sign <pkg> --key <private_key>\n";
    std::cout << "  airgapctl keygen --out <dir>\n";
    std::cout << "  airgapctl import <pkg> [--trusted-key <pub_key>]\n";
    std::cout << "  airgapctl install <name> --version <ver>\n";
    std::cout << "  airgapctl status\n";
    std::cout << "  airgapctl audit verify-chain\n";
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
        std::string pub_key_path = "keys/release.key.pub";
        for (int i = 3; i < argc; i++) {
            if (std::strcmp(argv[i], "--trusted-key") == 0) {
                auto v = getArg(i, argc, argv, "--trusted-key");
                if (!v) return 1; pub_key_path = v;
                } else {
                    std::cerr << clr::red("error:") << " unknown flag: " << argv[i] << std::endl;
                    return 1;
                }
            }

            Store store;
        store.open("airgap.db");
        AuditLog audit;
        audit.open("airgap.db");
        return verifyPackage(pkg_path, pub_key_path, &store, &audit);
    }

    if (std::strcmp(argv[1], "install") == 0) {
        if (argc < 4) {
            std::cerr << clr::red("error:") << " usage: airgapctl install <name> --version <ver>" << std::endl;
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

        if (!store.bundleImported(name, version)) {
            std::string reason = "bundle not imported";
            std::cerr << clr::red("error:") << " " << name << " " << version
                      << " has not been imported. Run 'airgapctl import' first." << std::endl;
            audit.writeEvent("PACKAGE_IMPORTED", name, version, "failed", reason, "");
            return 1;
        }

        std::string installed = store.getInstalledVersion(name);
        if (!installed.empty() && versionLessThan(version, installed)) {
            std::string reason = "version " + version + " is older than installed " + installed;
            std::cout << clr::fail("Install rejected: downgrade detected") << std::endl;
            std::cout << "  " << name << " " << version
                      << " is older than installed version " << installed << std::endl;
            audit.writeEvent("ROLLBACK_BLOCKED", name, version, "failed", reason, "");
            return 1;
        }

        std::string manifest_hash = store.getImportedManifestHash(name, version);
        store.installPackage(name, version, manifest_hash, installed);

        std::cout << clr::green("Installed:") << " " << clr::bold(name + " " + version) << std::endl;
        if (!installed.empty()) {
            std::cout << "  Previous version: " << installed << std::endl;
        }
        audit.writeEvent("PACKAGE_INSTALLED", name, version, "success", "", manifest_hash);
        return 0;
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
