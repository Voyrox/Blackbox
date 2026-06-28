package store

import (
    "os"
    "path/filepath"
    "testing"
)

func tempDB(t *testing.T) *Store {
    t.Helper()
    path := filepath.Join(t.TempDir(), "test.db")
    s, err := Open(path)
    if err != nil {
        t.Fatal(err)
    }
    t.Cleanup(func() { s.Close() })
    return s
}

func TestOpenCreatesTables(t *testing.T) {
    path := filepath.Join(t.TempDir(), "test.db")
    s, err := Open(path)
    if err != nil {
        t.Fatal(err)
    }
    defer s.Close()

    tables := []string{"installed_versions", "imported_bundles", "blocked_versions", "audit_events", "trusted_vendors"}
    for _, name := range tables {
        ok, err := s.HasTable(name)
        if err != nil {
            t.Fatal(err)
        }
        if !ok {
            t.Errorf("table %s not created", name)
        }
    }
}

func TestAddAndCheckImportedBundle(t *testing.T) {
    s := tempDB(t)
    s.AddImportedBundle("id1", "test-pkg", "1.0.0", "hash123", "pending")
    ok, err := s.BundleImported("test-pkg", "1.0.0")
    if err != nil {
        t.Fatal(err)
    }
    if !ok {
        t.Error("bundle should exist")
    }
    ok, err = s.BundleImported("test-pkg", "2.0.0")
    if err != nil {
        t.Fatal(err)
    }
    if ok {
        t.Error("bundle should not exist")
    }
}

func TestGetImportedManifestHash(t *testing.T) {
    s := tempDB(t)
    s.AddImportedBundle("id1", "pkg", "1.0.0", "manifest-hash-abc", "pending")
    h, err := s.GetImportedManifestHash("pkg", "1.0.0")
    if err != nil {
        t.Fatal(err)
    }
    if h != "manifest-hash-abc" {
        t.Errorf("hash = %s, want manifest-hash-abc", h)
    }
}

func TestSetAndGetBundleStatus(t *testing.T) {
    s := tempDB(t)
    s.AddImportedBundle("id1", "pkg", "1.0.0", "hash", "pending")
    s.SetBundleStatus("pkg", "1.0.0", "approved")
    st, _ := s.GetBundleStatus("pkg", "1.0.0")
    if st != "approved" {
        t.Errorf("status = %s, want approved", st)
    }
}

func TestInstallAndGetVersion(t *testing.T) {
    s := tempDB(t)
    s.InstallPackage("pkg", "1.0.0", "hash", "")
    v, err := s.GetInstalledVersion("pkg")
    if err != nil {
        t.Fatal(err)
    }
    if v != "1.0.0" {
        t.Errorf("version = %s, want 1.0.0", v)
    }
}

func TestInstallUpgradePreservesPrevious(t *testing.T) {
    s := tempDB(t)
    s.InstallPackage("pkg", "1.0.0", "hash", "")
    s.InstallPackage("pkg", "2.0.0", "hash2", "1.0.0")
    all, err := s.GetAllInstalled()
    if err != nil {
        t.Fatal(err)
    }
    if len(all) != 1 {
        t.Fatalf("got %d installed, want 1", len(all))
    }
    if all[0].PreviousVersion != "1.0.0" {
        t.Errorf("previous = %s, want 1.0.0", all[0].PreviousVersion)
    }
}

func TestGetAllImported(t *testing.T) {
    s := tempDB(t)
    s.AddImportedBundle("a", "p1", "1.0", "h1", "pending")
    s.AddImportedBundle("b", "p2", "2.0", "h2", "approved")
    all, err := s.GetAllImported()
    if err != nil {
        t.Fatal(err)
    }
    if len(all) != 2 {
        t.Fatalf("got %d, want 2", len(all))
    }
}

func TestBlockAndUnblockVersion(t *testing.T) {
    s := tempDB(t)
    err := s.AddBlockedVersion("lib", "1.0.0", "CVE-1234")
    if err != nil {
        t.Fatal(err)
    }
    blocked, _ := s.IsVersionBlocked("lib", "1.0.0")
    if !blocked {
        t.Error("expected version to be blocked")
    }
    r, _ := s.GetBlockedReason("lib", "1.0.0")
    if r != "CVE-1234" {
        t.Errorf("reason = %s, want CVE-1234", r)
    }
    s.RemoveBlockedVersion("lib", "1.0.0")
    blocked, _ = s.IsVersionBlocked("lib", "1.0.0")
    if blocked {
        t.Error("expected version to be unblocked")
    }
}

func TestListBlockedVersions(t *testing.T) {
    s := tempDB(t)
    s.AddBlockedVersion("a", "1.0", "reason a")
    s.AddBlockedVersion("b", "2.0", "reason b")
    list, err := s.ListBlockedVersions()
    if err != nil {
        t.Fatal(err)
    }
    if len(list) != 2 {
        t.Fatalf("got %d, want 2", len(list))
    }
}

func TestIsVersionBlockedInitially(t *testing.T) {
    s := tempDB(t)
    blocked, _ := s.IsVersionBlocked("anything", "1.0.0")
    if blocked {
        t.Error("expected no versions to be blocked initially")
    }
}

func TestAddAndListTrustedVendor(t *testing.T) {
    s := tempDB(t)
    pem := "-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----"
    s.AddTrustedVendor("Acme Corp", pem)
    vendors, err := s.ListTrustedVendors()
    if err != nil {
        t.Fatal(err)
    }
    if len(vendors) != 1 {
        t.Fatalf("got %d vendors, want 1", len(vendors))
    }
    if vendors[0].Name != "Acme Corp" {
        t.Errorf("name = %s, want Acme Corp", vendors[0].Name)
    }
}

func TestListTrustedVendorsEmpty(t *testing.T) {
    s := tempDB(t)
    vendors, _ := s.ListTrustedVendors()
    if len(vendors) != 0 {
        t.Errorf("expected empty, got %d", len(vendors))
    }
}

func TestRemoveTrustedVendor(t *testing.T) {
    s := tempDB(t)
    s.AddTrustedVendor("Acme Corp", "pem-data")
    s.RemoveTrustedVendor("Acme Corp")
    vendors, _ := s.ListTrustedVendors()
    if len(vendors) != 0 {
        t.Error("vendor should have been removed")
    }
}

func TestAddTrustedVendorComputesFingerprint(t *testing.T) {
    s := tempDB(t)
    pem := "-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----"
    s.AddTrustedVendor("Test Vendor", pem)
    vendors, _ := s.ListTrustedVendors()
    if len(vendors) == 0 {
        t.Fatal("vendor not found")
    }
    if vendors[0].Fingerprint == "" {
        t.Error("fingerprint should be computed")
    }
}

func TestGetAllVendorKeysReturnsNameAndPem(t *testing.T) {
    s := tempDB(t)
    s.AddTrustedVendor("v1", "pem1")
    s.AddTrustedVendor("v2", "pem2")
    keys, err := s.GetAllVendorKeys()
    if err != nil {
        t.Fatal(err)
    }
    if len(keys) != 2 {
        t.Fatalf("got %d, want 2", len(keys))
    }
}

func TestRollbackTransactionOnFailure(t *testing.T) {
    path := filepath.Join(t.TempDir(), "test.db")
    s, err := Open(path)
    if err != nil {
        t.Fatal(err)
    }
    defer s.Close()

    s.BeginTransaction()
    s.AddImportedBundle("id1", "pkg", "1.0", "hash", "pending")
    s.RollbackTransaction()

    ok, _ := s.BundleImported("pkg", "1.0")
    if ok {
        t.Error("bundle should not exist after rollback")
    }
}

func TestCommitTransactionPersists(t *testing.T) {
    path := filepath.Join(t.TempDir(), "test.db")
    s, err := Open(path)
    if err != nil {
        t.Fatal(err)
    }
    s.BeginTransaction()
    s.InstallPackage("pkg", "1.0", "hash", "")
    s.CommitTransaction()
    s.Close()

    s2, err := Open(path)
    if err != nil {
        t.Fatal(err)
    }
    defer s2.Close()
    v, _ := s2.GetInstalledVersion("pkg")
    if v != "1.0" {
        t.Errorf("version = %s, want 1.0", v)
    }
}

func TestTempDirEnv(t *testing.T) {
    
    path := filepath.Join(t.TempDir(), "test.db")
    s, err := Open(path)
    if err != nil {
        t.Fatal(err)
    }
    s.Close()
    if _, err := os.Stat(path); os.IsNotExist(err) {
        t.Error("db file should exist")
    }
}
