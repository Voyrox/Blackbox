package store

import (
    "crypto/sha256"
    "database/sql"
    "fmt"
    "time"

    _ "modernc.org/sqlite"
)

type TrustedVendor struct {
    Name        string
    PublicKeyPEM string
    Fingerprint string
    AddedAt     string
}

type ImportedBundle struct {
    ID           string
    PackageName  string
    Version      string
    ManifestHash string
    Status       string
    ImportedAt   string
}

type InstalledPackage struct {
    PackageName    string
    Version        string
    PreviousVersion string
    InstalledAt    string
}

type BlockedVersion struct {
    PackageName string
    Version     string
    Reason      string
    BlockedAt   string
}

type Store struct {
    db *sql.DB
}

func Open(path string) (*Store, error) {
    db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
    if err != nil {
        return nil, fmt.Errorf("open db: %w", err)
    }
    s := &Store{db: db}
    if err := s.migrate(); err != nil {
        db.Close()
        return nil, fmt.Errorf("migrate: %w", err)
    }
    return s, nil
}

func (s *Store) Close() error {
    return s.db.Close()
}

func (s *Store) migrate() error {
    tables := []string{
        `CREATE TABLE IF NOT EXISTS installed_versions (
            package_name TEXT PRIMARY KEY,
            current_version TEXT NOT NULL,
            previous_version TEXT,
            installed_at TEXT NOT NULL,
            manifest_hash TEXT NOT NULL DEFAULT ''
        )`,
        `CREATE TABLE IF NOT EXISTS imported_bundles (
            id TEXT PRIMARY KEY,
            package_name TEXT NOT NULL,
            version TEXT NOT NULL,
            manifest_hash TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            imported_at TEXT NOT NULL
        )`,
        `CREATE TABLE IF NOT EXISTS blocked_versions (
            package_name TEXT,
            version TEXT,
            blocked_at TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (package_name, version)
        )`,
        `CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            actor TEXT NOT NULL DEFAULT '',
            action TEXT NOT NULL,
            package_name TEXT NOT NULL DEFAULT '',
            version TEXT NOT NULL DEFAULT '',
            result TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '',
            meta TEXT NOT NULL DEFAULT '',
            previous_hash TEXT NOT NULL DEFAULT '',
            hash TEXT NOT NULL DEFAULT ''
        )`,
        `CREATE TABLE IF NOT EXISTS trusted_vendors (
            name TEXT PRIMARY KEY,
            public_key_pem TEXT NOT NULL,
            fingerprint TEXT NOT NULL DEFAULT '',
            added_at TEXT NOT NULL
        )`,
    }
    for _, t := range tables {
        if _, err := s.db.Exec(t); err != nil {
            return err
        }
    }
    return nil
}

func (s *Store) AddImportedBundle(id, pkg, version, manifestHash, status string) error {
    _, err := s.db.Exec(`INSERT INTO imported_bundles (id, package_name, version, manifest_hash, status, imported_at) VALUES (?, ?, ?, ?, ?, ?)`,
        id, pkg, version, manifestHash, status, time.Now().UTC().Format("2006-01-02 15:04:05"))
    return err
}

func (s *Store) BundleImported(pkg, version string) (bool, error) {
    var cnt int
    err := s.db.QueryRow(`SELECT COUNT(*) FROM imported_bundles WHERE package_name = ? AND version = ?`, pkg, version).Scan(&cnt)
    if err != nil {
        return false, err
    }
    return cnt > 0, nil
}

func (s *Store) GetImportedManifestHash(pkg, version string) (string, error) {
    var h string
    err := s.db.QueryRow(`SELECT manifest_hash FROM imported_bundles WHERE package_name = ? AND version = ?`, pkg, version).Scan(&h)
    if err == sql.ErrNoRows {
        return "", nil
    }
    return h, err
}

func (s *Store) GetAllImported() ([]ImportedBundle, error) {
    rows, err := s.db.Query(`SELECT id, package_name, version, manifest_hash, status, imported_at FROM imported_bundles ORDER BY imported_at DESC`)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    var result []ImportedBundle
    for rows.Next() {
        var b ImportedBundle
        if err := rows.Scan(&b.ID, &b.PackageName, &b.Version, &b.ManifestHash, &b.Status, &b.ImportedAt); err != nil {
            return nil, err
        }
        result = append(result, b)
    }
    return result, rows.Err()
}

func (s *Store) GetInstalledVersion(pkg string) (string, error) {
    var v string
    err := s.db.QueryRow(`SELECT current_version FROM installed_versions WHERE package_name = ?`, pkg).Scan(&v)
    if err == sql.ErrNoRows {
        return "", nil
    }
    return v, err
}

func (s *Store) InstallPackage(pkg, version, manifestHash, previous string) error {
    _, err := s.db.Exec(`INSERT OR REPLACE INTO installed_versions (package_name, current_version, previous_version, installed_at, manifest_hash) VALUES (?, ?, ?, ?, ?)`,
        pkg, version, previous, time.Now().UTC().Format("2006-01-02 15:04:05"), manifestHash)
    return err
}

func (s *Store) GetAllInstalled() ([]InstalledPackage, error) {
    rows, err := s.db.Query(`SELECT package_name, current_version, previous_version, installed_at FROM installed_versions ORDER BY installed_at DESC`)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    var result []InstalledPackage
    for rows.Next() {
        var p InstalledPackage
        if err := rows.Scan(&p.PackageName, &p.Version, &p.PreviousVersion, &p.InstalledAt); err != nil {
            return nil, err
        }
        result = append(result, p)
    }
    return result, rows.Err()
}

func (s *Store) AddBlockedVersion(pkg, version, reason string) error {
    _, err := s.db.Exec(`INSERT OR REPLACE INTO blocked_versions (package_name, version, blocked_at, reason) VALUES (?, ?, ?, ?)`,
        pkg, version, time.Now().UTC().Format("2006-01-02 15:04:05"), reason)
    return err
}

func (s *Store) RemoveBlockedVersion(pkg, version string) error {
    _, err := s.db.Exec(`DELETE FROM blocked_versions WHERE package_name = ? AND version = ?`, pkg, version)
    return err
}

func (s *Store) ListBlockedVersions() ([]BlockedVersion, error) {
    rows, err := s.db.Query(`SELECT package_name, version, reason, blocked_at FROM blocked_versions ORDER BY blocked_at DESC`)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    var result []BlockedVersion
    for rows.Next() {
        var b BlockedVersion
        if err := rows.Scan(&b.PackageName, &b.Version, &b.Reason, &b.BlockedAt); err != nil {
            return nil, err
        }
        result = append(result, b)
    }
    return result, rows.Err()
}

func (s *Store) GetBlockedReason(pkg, version string) (string, error) {
    var r string
    err := s.db.QueryRow(`SELECT reason FROM blocked_versions WHERE package_name = ? AND version = ?`, pkg, version).Scan(&r)
    if err == sql.ErrNoRows {
        return "", nil
    }
    return r, err
}

func (s *Store) IsVersionBlocked(pkg, version string) (bool, error) {
    var cnt int
    err := s.db.QueryRow(`SELECT COUNT(*) FROM blocked_versions WHERE package_name = ? AND version = ?`, pkg, version).Scan(&cnt)
    if err != nil {
        return false, err
    }
    return cnt > 0, nil
}

func (s *Store) SetBundleStatus(pkg, version, status string) error {
    _, err := s.db.Exec(`UPDATE imported_bundles SET status = ? WHERE package_name = ? AND version = ?`, status, pkg, version)
    return err
}

func (s *Store) GetBundleStatus(pkg, version string) (string, error) {
    var st string
    err := s.db.QueryRow(`SELECT status FROM imported_bundles WHERE package_name = ? AND version = ?`, pkg, version).Scan(&st)
    if err == sql.ErrNoRows {
        return "", nil
    }
    return st, err
}

func (s *Store) BeginTransaction() error {
    _, err := s.db.Exec(`BEGIN`)
    return err
}

func (s *Store) CommitTransaction() error {
    _, err := s.db.Exec(`COMMIT`)
    return err
}

func (s *Store) RollbackTransaction() error {
    _, err := s.db.Exec(`ROLLBACK`)
    return err
}

func (s *Store) AddTrustedVendor(name, publicKeyPEM string) error {
    fp := sha256.Sum256([]byte(publicKeyPEM))
    fingerprint := fmt.Sprintf("%x", fp)
    _, err := s.db.Exec(`INSERT INTO trusted_vendors (name, public_key_pem, fingerprint, added_at) VALUES (?, ?, ?, ?)`,
        name, publicKeyPEM, fingerprint, time.Now().UTC().Format("2006-01-02 15:04:05"))
    return err
}

func (s *Store) RemoveTrustedVendor(name string) error {
    _, err := s.db.Exec(`DELETE FROM trusted_vendors WHERE name = ?`, name)
    return err
}

func (s *Store) ListTrustedVendors() ([]TrustedVendor, error) {
    rows, err := s.db.Query(`SELECT name, public_key_pem, fingerprint, added_at FROM trusted_vendors ORDER BY added_at DESC`)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    var result []TrustedVendor
    for rows.Next() {
        var v TrustedVendor
        if err := rows.Scan(&v.Name, &v.PublicKeyPEM, &v.Fingerprint, &v.AddedAt); err != nil {
            return nil, err
        }
        result = append(result, v)
    }
    return result, rows.Err()
}

func (s *Store) GetAllVendorKeys() ([]struct{ Name, PublicKeyPEM string }, error) {
    rows, err := s.db.Query(`SELECT name, public_key_pem FROM trusted_vendors`)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    var result []struct{ Name, PublicKeyPEM string }
    for rows.Next() {
        var name, pem string
        if err := rows.Scan(&name, &pem); err != nil {
            return nil, err
        }
        result = append(result, struct{ Name, PublicKeyPEM string }{name, pem})
    }
    return result, rows.Err()
}

func (s *Store) HasTable(name string) (bool, error) {
    var cnt int
    err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&cnt)
    if err != nil {
        return false, err
    }
    return cnt > 0, nil
}
