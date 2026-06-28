package audit

import (
    "os"
    "path/filepath"
    "testing"
)

func tempAudit(t *testing.T) *AuditLog {
    t.Helper()
    path := filepath.Join(t.TempDir(), "audit.db")
    a, err := Open(path)
    if err != nil {
        t.Fatal(err)
    }
    t.Cleanup(func() { a.Close() })
    return a
}

func TestOpenCreatesTables(t *testing.T) {
    path := filepath.Join(t.TempDir(), "audit.db")
    a, err := Open(path)
    if err != nil {
        t.Fatal(err)
    }
    defer a.Close()

    var cnt int
    err = a.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='audit_events'`).Scan(&cnt)
    if err != nil {
        t.Fatal(err)
    }
    if cnt == 0 {
        t.Error("audit_events table not created")
    }
}

func TestWriteEvent(t *testing.T) {
    a := tempAudit(t)
    id, err := a.WriteEvent("test-actor", "TEST_ACTION", "pkg", "1.0", "success", "", "meta")
    if err != nil {
        t.Fatal(err)
    }
    if len(id) == 0 {
        t.Error("expected non-empty audit ID")
    }
}

func TestVerifyEmptyChain(t *testing.T) {
    a := tempAudit(t)
    valid, count, err := a.VerifyChain()
    if err != nil {
        t.Fatal(err)
    }
    if !valid {
        t.Error("empty chain should be valid")
    }
    if count != 0 {
        t.Errorf("count = %d, want 0", count)
    }
}

func TestVerifyChainSingleEvent(t *testing.T) {
    a := tempAudit(t)
    a.WriteEvent("actor", "ACTION", "pkg", "1.0", "success", "", "")
    valid, count, err := a.VerifyChain()
    if err != nil {
        t.Fatal(err)
    }
    if !valid {
        t.Error("single event chain should be valid")
    }
    if count != 1 {
        t.Errorf("count = %d, want 1", count)
    }
}

func TestVerifyChainMultipleEvents(t *testing.T) {
    a := tempAudit(t)
    a.WriteEvent("actor", "ACTION_A", "pkg", "1.0", "success", "", "")
    a.WriteEvent("actor", "ACTION_B", "pkg", "1.0", "success", "", "")
    a.WriteEvent("actor", "ACTION_C", "pkg", "1.0", "success", "", "")
    valid, count, _ := a.VerifyChain()
    if !valid {
        t.Error("chain should be valid")
    }
    if count != 3 {
        t.Errorf("count = %d, want 3", count)
    }
}

func TestTamperDetection(t *testing.T) {
    a := tempAudit(t)
    a.WriteEvent("actor", "ACTION", "pkg", "1.0", "success", "", "")
    a.WriteEvent("actor", "ACTION2", "pkg", "1.0", "success", "", "")

    // Tamper with the first event's action
    a.db.Exec(`UPDATE audit_events SET action = 'TAMPERED' WHERE id = 1`)

    valid, _, _ := a.VerifyChain()
    if valid {
        t.Error("chain should be invalid after tampering")
    }
}

func TestCount(t *testing.T) {
    a := tempAudit(t)
    a.WriteEvent("a", "ACT", "p", "1", "s", "", "")
    a.WriteEvent("b", "ACT", "p", "1", "s", "", "")
    cnt, err := a.Count()
    if err != nil {
        t.Fatal(err)
    }
    if cnt != 2 {
        t.Errorf("count = %d, want 2", cnt)
    }
}

func TestTempDirEnv(t *testing.T) {
    path := filepath.Join(t.TempDir(), "audit.db")
    a, err := Open(path)
    if err != nil {
        t.Fatal(err)
    }
    a.Close()
    if _, err := os.Stat(path); os.IsNotExist(err) {
        t.Error("audit db file should exist")
    }
}
