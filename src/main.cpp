#include <iostream>

int main(int argc, char* argv[]) {
    if (argc) {

    } else {
      std::cout << "Usage: airgapctl package create --name <name> --version <version> --payload <payload_path> --sbom <sbom_path> --out <output_path>" << std::endl;
    }
}
