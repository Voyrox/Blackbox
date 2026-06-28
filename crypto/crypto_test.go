package crypto

import (
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func TestSHA256DataKnownValues(t *testing.T) {
    tests := []struct {
        input string
        len   int
    }{
        {"hello", 64},
        {"", 64},
        {"The quick brown fox jumps over the lazy dog", 64},
    }
    for _, tc := range tests {
        h := SHA256Data(tc.input)
        if len(h) != tc.len {
            t.Errorf("SHA256Data(%q) length = %d, want %d", tc.input, len(h), tc.len)
        }
    }
}

func TestSHA256DataConsistency(t *testing.T) {
    h1 := SHA256Data("hello")
    h2 := SHA256Data("hello")
    if h1 != h2 {
        t.Error("SHA256Data not consistent")
    }
    h3 := SHA256Data("world")
    if h1 == h3 {
        t.Error("SHA256Data should differ for different inputs")
    }
}

func TestSHA256File(t *testing.T) {
    dir := t.TempDir()
    path := filepath.Join(dir, "test.txt")
    os.WriteFile(path, []byte("hello"), 0644)
    h, err := SHA256File(path)
    if err != nil {
        t.Fatal(err)
    }
    expected := SHA256Data("hello")
    if h != expected {
        t.Errorf("SHA256File = %s, want %s", h, expected)
    }
}

func TestSHA256FileNotFound(t *testing.T) {
    _, err := SHA256File("/nonexistent/file")
    if err == nil {
        t.Error("expected error for nonexistent file")
    }
}

func TestKeygenSignVerify(t *testing.T) {
    dir := t.TempDir()
    privPath := filepath.Join(dir, "key")
    pubPath := filepath.Join(dir, "key.pub")
    filePath := filepath.Join(dir, "data.bin")
    sigPath := filepath.Join(dir, "data.bin.sig")

    if err := GenerateKeypair(privPath, pubPath); err != nil {
        t.Fatal(err)
    }
    if _, err := os.Stat(privPath); os.IsNotExist(err) {
        t.Error("private key not created")
    }
    if _, err := os.Stat(pubPath); os.IsNotExist(err) {
        t.Error("public key not created")
    }

    os.WriteFile(filePath, []byte("test data for signing"), 0644)
    if err := SignFile(filePath, privPath, sigPath); err != nil {
        t.Fatal(err)
    }
    if _, err := os.Stat(sigPath); os.IsNotExist(err) {
        t.Error("signature not created")
    }

    ok, err := VerifyFile(filePath, sigPath, pubPath)
    if err != nil {
        t.Fatal(err)
    }
    if !ok {
        t.Error("signature verification failed")
    }
}

func TestVerifyTamperedFile(t *testing.T) {
    dir := t.TempDir()
    privPath := filepath.Join(dir, "key")
    pubPath := filepath.Join(dir, "key.pub")
    filePath := filepath.Join(dir, "data.bin")
    sigPath := filepath.Join(dir, "data.bin.sig")

    GenerateKeypair(privPath, pubPath)
    os.WriteFile(filePath, []byte("original content"), 0644)
    SignFile(filePath, privPath, sigPath)

    os.WriteFile(filePath, []byte("tampered content"), 0644)
    ok, err := VerifyFile(filePath, sigPath, pubPath)
    if err != nil {
        t.Fatal(err)
    }
    if ok {
        t.Error("expected verification to fail for tampered file")
    }
}

func TestVerifyFileWithKey(t *testing.T) {
    dir := t.TempDir()
    privPath := filepath.Join(dir, "key")
    pubPath := filepath.Join(dir, "key.pub")
    filePath := filepath.Join(dir, "data.bin")
    sigPath := filepath.Join(dir, "data.bin.sig")

    GenerateKeypair(privPath, pubPath)
    os.WriteFile(filePath, []byte("content"), 0644)
    SignFile(filePath, privPath, sigPath)

    pubPEM, _ := os.ReadFile(pubPath)
    ok, err := VerifyFileWithKey(filePath, sigPath, string(pubPEM))
    if err != nil {
        t.Fatal(err)
    }
    if !ok {
        t.Error("VerifyFileWithKey failed")
    }
}

func TestKeygenKeyFormat(t *testing.T) {
    dir := t.TempDir()
    privPath := filepath.Join(dir, "key")
    pubPath := filepath.Join(dir, "key.pub")

    GenerateKeypair(privPath, pubPath)
    privData, _ := os.ReadFile(privPath)
    if !strings.Contains(string(privData), "EC PRIVATE KEY") {
        t.Error("private key PEM missing header")
    }
    pubData, _ := os.ReadFile(pubPath)
    if !strings.Contains(string(pubData), "PUBLIC KEY") {
        t.Error("public key PEM missing header")
    }
}
