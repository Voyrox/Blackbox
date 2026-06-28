package archive

import (
    "os"
    "path/filepath"
    "testing"
)

func TestEqualVersions(t *testing.T) {
    if VersionLessThan("1.0.0", "1.0.0") {
        t.Error("1.0.0 should not be less than 1.0.0")
    }
}

func TestMajorVersionComparison(t *testing.T) {
    if !VersionLessThan("1.0.0", "2.0.0") {
        t.Error("1.0.0 should be less than 2.0.0")
    }
    if VersionLessThan("2.0.0", "1.0.0") {
        t.Error("2.0.0 should not be less than 1.0.0")
    }
}

func TestMinorVersionComparison(t *testing.T) {
    if !VersionLessThan("1.2.0", "1.3.0") {
        t.Error("1.2.0 should be less than 1.3.0")
    }
}

func TestPatchVersionComparison(t *testing.T) {
    if !VersionLessThan("1.0.1", "1.0.2") {
        t.Error("1.0.1 should be less than 1.0.2")
    }
}

func TestMultiDigitVersions(t *testing.T) {
    if !VersionLessThan("10.0.0", "11.0.0") {
        t.Error("10.0.0 should be less than 11.0.0")
    }
}

func TestEmptyVersion(t *testing.T) {
    if !VersionLessThan("", "1.0.0") {
        t.Error("empty version should be less than 1.0.0")
    }
    if VersionLessThan("1.0.0", "") {
        t.Error("1.0.0 should not be less than empty version")
    }
}

func TestISO8601Now(t *testing.T) {
    s := ISO8601Now()
    if len(s) < 10 {
        t.Errorf("ISO8601Now too short: %s", s)
    }
    if s[4] != '-' || s[7] != '-' {
        t.Errorf("ISO8601Now unexpected format: %s", s)
    }
}

func createTestPayload(t *testing.T, dir string) {
    t.Helper()
    os.MkdirAll(filepath.Join(dir, "bin"), 0755)
    os.WriteFile(filepath.Join(dir, "bin", "agent"), []byte("fake binary"), 0644)
    os.MkdirAll(filepath.Join(dir, "config"), 0755)
    os.WriteFile(filepath.Join(dir, "config", "settings.yml"), []byte("key: value"), 0644)
    os.WriteFile(filepath.Join(dir, "install.sh"), []byte("#!/bin/sh\necho install"), 0755)
}

func TestCreatePackage(t *testing.T) {
    dir := t.TempDir()
    payloadDir := filepath.Join(dir, "payload")
    sbomPath := filepath.Join(dir, "sbom.json")
    outputPath := filepath.Join(dir, "output.agpkg")

    createTestPayload(t, payloadDir)
    os.WriteFile(sbomPath, []byte(`{"bomFormat":"SPDX","name":"test"}`), 0644)

    err := CreatePackage("test-pkg", "1.0.0", payloadDir, sbomPath, outputPath)
    if err != nil {
        t.Fatal(err)
    }

    if _, err := os.Stat(outputPath); os.IsNotExist(err) {
        t.Fatal("output file not created")
    }

    m, err := ReadManifest(outputPath)
    if err != nil {
        t.Fatal(err)
    }
    if m.PackageName != "test-pkg" {
        t.Errorf("package_name = %s, want test-pkg", m.PackageName)
    }
    if m.Version != "1.0.0" {
        t.Errorf("version = %s, want 1.0.0", m.Version)
    }
    if m.CreatedBy != "blackbox" {
        t.Errorf("created_by = %s, want blackbox", m.CreatedBy)
    }
}

func TestCreatePackageHashMatches(t *testing.T) {
    dir := t.TempDir()
    payloadDir := filepath.Join(dir, "payload")
    sbomPath := filepath.Join(dir, "sbom.json")
    outputPath := filepath.Join(dir, "output.agpkg")

    createTestPayload(t, payloadDir)
    os.WriteFile(sbomPath, []byte(`{"bomFormat":"SPDX"}`), 0644)

    CreatePackage("pkg", "1.0.0", payloadDir, sbomPath, outputPath)
    m, _ := ReadManifest(outputPath)

    
    expectedPayloadHash, _ := HashPayload(payloadDir)
    if m.PayloadHash != "sha256:"+expectedPayloadHash {
        t.Errorf("payload_hash = %s, want sha256:%s", m.PayloadHash, expectedPayloadHash)
    }
}
