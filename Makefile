BUILD_DIR = build
BINARY = $(BUILD_DIR)/airgapctl

.PHONY: all run clean

all:
	cmake -B $(BUILD_DIR) -G Ninja
	cmake --build $(BUILD_DIR)

run: all
	mkdir -p keys dist
	$(BINARY) keygen --out keys
	$(BINARY) package create \
		--name ics-firmware-v2 \
		--version 2.3.1 \
		--payload test_payload \
		--sbom test_sbom.json \
		--out dist/ics-firmware-v2-2.3.1.agpkg
	$(BINARY) package sign dist/ics-firmware-v2-2.3.1.agpkg --key keys/release.key
	$(BINARY) import dist/ics-firmware-v2-2.3.1.agpkg --trusted-key keys/release.key.pub
	$(BINARY) approve ics-firmware-v2 --version 2.3.1
	$(BINARY) install ics-firmware-v2 --version 2.3.1
	$(BINARY) status

clean:
	rm -rf $(BUILD_DIR) dist keys *.db