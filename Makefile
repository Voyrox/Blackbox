BINARY = blackbox

.PHONY: all test run clean

all:
	go build -o $(BINARY) .

test:
	go test ./... -v

run: all
	if not exist keys mkdir keys
	if not exist dist mkdir dist
	./$(BINARY) keygen --out keys
	./$(BINARY) package create \
		--name ics-firmware-v2 \
		--version 2.3.1 \
		--payload test_payload \
		--sbom test_sbom.json \
		--out dist/ics-firmware-v2-2.3.1.agpkg
	./$(BINARY) package sign dist/ics-firmware-v2-2.3.1.agpkg --key keys/release.key
	./$(BINARY) trust add keys/release.key.pub --name "Internal Dev"
	./$(BINARY) import dist/ics-firmware-v2-2.3.1.agpkg
	./$(BINARY) approve ics-firmware-v2 --version 2.3.1
	./$(BINARY) install ics-firmware-v2 --version 2.3.1
	./$(BINARY) status

clean:
	rm -rf $(BINARY) dist keys *.db
