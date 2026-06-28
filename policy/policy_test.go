package policy

import (
    "path/filepath"
    "testing"

    "blackbox/archive"
    "blackbox/store"
)

func tempStore(t *testing.T) *store.Store {
    t.Helper()
    path := filepath.Join(t.TempDir(), "test.db")
    s, err := store.Open(path)
    if err != nil {
        t.Fatal(err)
    }
    t.Cleanup(func() { s.Close() })
    return s
}

func TestNoDependenciesReturnsEmpty(t *testing.T) {
    s := tempStore(t)
    results, err := CheckDependencies(s, nil)
    if err != nil {
        t.Fatal(err)
    }
    if len(results) != 0 {
        t.Errorf("got %d results, want 0", len(results))
    }
}

func TestAllDepsAllowed(t *testing.T) {
    s := tempStore(t)
    deps := []archive.Dependency{
        {Name: "lib-a", Version: "1.0.0"},
        {Name: "lib-b", Version: "2.0.0"},
    }
    results, err := CheckDependencies(s, deps)
    if err != nil {
        t.Fatal(err)
    }
    if len(results) != 2 {
        t.Fatalf("got %d results, want 2", len(results))
    }
    for _, r := range results {
        if r.Blocked {
            t.Errorf("%s %s should not be blocked", r.DependencyName, r.DependencyVersion)
        }
    }
}

func TestBlockedDepDetected(t *testing.T) {
    s := tempStore(t)
    s.AddBlockedVersion("lib-a", "1.0.0", "CVE-1234")
    deps := []archive.Dependency{
        {Name: "lib-a", Version: "1.0.0"},
        {Name: "lib-b", Version: "2.0.0"},
    }
    results, err := CheckDependencies(s, deps)
    if err != nil {
        t.Fatal(err)
    }
    if len(results) != 2 {
        t.Fatalf("got %d results, want 2", len(results))
    }
    for _, r := range results {
        if r.DependencyName == "lib-a" && !r.Blocked {
            t.Error("lib-a should be blocked")
        }
        if r.DependencyName == "lib-b" && r.Blocked {
            t.Error("lib-b should not be blocked")
        }
    }
}

func TestNullStoreReturnsEmpty(t *testing.T) {
    results, err := CheckDependencies(nil, []archive.Dependency{{Name: "a", Version: "1.0"}})
    if err != nil {
        t.Fatal(err)
    }
    if len(results) != 0 {
        t.Errorf("got %d results, want 0", len(results))
    }
}

func TestBlockedVersionDifferentVersionNotAffected(t *testing.T) {
    s := tempStore(t)
    s.AddBlockedVersion("lib-a", "1.0.0", "CVE-1234")
    deps := []archive.Dependency{
        {Name: "lib-a", Version: "1.5.0"},
    }
    results, err := CheckDependencies(s, deps)
    if err != nil {
        t.Fatal(err)
    }
    if len(results) != 1 {
        t.Fatalf("got %d results, want 1", len(results))
    }
    if results[0].Blocked {
        t.Error("lib-a 1.5.0 should not be blocked (only 1.0.0 is blocked)")
    }
}
