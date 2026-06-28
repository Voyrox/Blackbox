BINARY = blackbox

.PHONY: all test run install clean

all:
	go build -o $(BINARY) .

test:
	go test ./... -v

run: all
	if not exist keys mkdir keys
	if not exist dist mkdir dist
	./$(BINARY) keygen --out keys
	./$(BINARY) package create --name ics-firmware-v2 --version 2.3.1 --payload test_payload --sbom test_sbom.json --out dist/ics-firmware-v2-2.3.1.agpkg
	./$(BINARY) package sign dist/ics-firmware-v2-2.3.1.agpkg --key keys/release.key
	./$(BINARY) trust add keys/release.key.pub --name "Internal Dev"
	./$(BINARY) install dist/ics-firmware-v2-2.3.1.agpkg
	./$(BINARY) status

install: all
	copy /y $(BINARY).exe "%USERPROFILE%\AppData\Local\Microsoft\WindowsApps\$(BINARY).exe" 2>nul || copy /y $(BINARY).exe "%USERPROFILE%\go\bin\$(BINARY).exe" 2>nul || echo "Warning: could not install to PATH"

clean:
	if exist $(BINARY).exe del /q $(BINARY).exe
	if exist $(BINARY) del /q $(BINARY)
	if exist dist rmdir /s /q dist
	if exist keys rmdir /s /q keys
	if exist *.db del /q *.db
