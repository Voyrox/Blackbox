BUILD_DIR = build
BINARY = $(BUILD_DIR)/blackbox
PREFIX ?= /usr/local

.PHONY: all test run install clean format

all:
	-cmake -E remove_directory $(BUILD_DIR)
	cmake -B $(BUILD_DIR) -G Ninja
	cmake --build $(BUILD_DIR)

run: all
	cmake -E make_directory keys dist
	$(BINARY) keygen --out keys
	$(BINARY) package create \
		--name ics-firmware-v2 \
		--version 2.3.1 \
		--payload test_payload \
		--sbom test_sbom.json \
		--out dist/ics-firmware-v2-2.3.1.agpkg
	$(BINARY) package sign dist/ics-firmware-v2-2.3.1.agpkg --key keys/release.key
	$(BINARY) trust add keys/release.key.pub --name "Internal Dev"
	$(BINARY) import dist/ics-firmware-v2-2.3.1.agpkg
	$(BINARY) approve ics-firmware-v2 --version 2.3.1
	$(BINARY) install ics-firmware-v2 --version 2.3.1
	$(BINARY) status

install: all
	cmake -E make_directory $(DESTDIR)$(PREFIX)/bin
	-cmake -E copy $(BINARY) $(DESTDIR)$(PREFIX)/bin/
	-cmake -E copy $(BINARY).exe $(DESTDIR)$(PREFIX)/bin/

test: all
	cd $(BUILD_DIR) && ctest --output-on-failure

format:
	clang-format -i src/*.hpp src/*.cpp src/*/*.hpp src/*/*.cpp tests/*.cpp

clean:
	rm -rf $(BUILD_DIR) dist keys *.db