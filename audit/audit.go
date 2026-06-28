package audit

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type AuditLog struct {
	db *sql.DB
}

type Event struct {
	ID          int
	Timestamp   string
	Actor       string
	Action      string
	PackageName string
	Version     string
	Result      string
	Reason      string
	Meta        string
	PrevHash    string
	Hash        string
}

func Open(path string) (*AuditLog, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open audit db: %w", err)
	}
	a := &AuditLog{db: db}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS audit_events (
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
    )`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create audit table: %w", err)
	}
	return a, nil
}

func (a *AuditLog) Close() error {
	return a.db.Close()
}

func computeHash(ts, actor, action, pkg, ver, result, reason, meta, prevHash string) string {
	combined := ts + "|" + actor + "|" + action + "|" + pkg + "|" + ver + "|" + result + "|" + reason + "|" + meta + "|" + prevHash
	h := sha256.Sum256([]byte(combined))
	return fmt.Sprintf("%x", h)
}

func (a *AuditLog) WriteEvent(actor, action, pkg, version, result, reason, meta string) (string, error) {
	var prevHash string
	err := a.db.QueryRow(`SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1`).Scan(&prevHash)
	if err != nil && err != sql.ErrNoRows {
		return "", fmt.Errorf("get previous hash: %w", err)
	}

	ts := time.Now().UTC().Format("2006-01-02 15:04:05")
	hash := computeHash(ts, actor, action, pkg, version, result, reason, meta, prevHash)

	_, err = a.db.Exec(`INSERT INTO audit_events (timestamp, actor, action, package_name, version, result, reason, meta, previous_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ts, actor, action, pkg, version, result, reason, meta, prevHash, hash)
	if err != nil {
		return "", err
	}
	return hash[:7], nil
}

func (a *AuditLog) VerifyChain() (bool, int, error) {
	rows, err := a.db.Query(`SELECT id, timestamp, actor, action, package_name, version, result, reason, meta, previous_hash, hash FROM audit_events ORDER BY id ASC`)
	if err != nil {
		return false, 0, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	var prevHash string
	count := 0
	chainValid := true

	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Actor, &e.Action, &e.PackageName, &e.Version, &e.Result, &e.Reason, &e.Meta, &e.PrevHash, &e.Hash); err != nil {
			return false, count, fmt.Errorf("scan event: %w", err)
		}
		count++

		if count == 1 {
			if e.PrevHash != "" {
				chainValid = false
			}
		} else {
			if e.PrevHash != prevHash {
				chainValid = false
			}
		}

		expected := computeHash(e.Timestamp, e.Actor, e.Action, e.PackageName, e.Version, e.Result, e.Reason, e.Meta, e.PrevHash)
		if expected != e.Hash {
			chainValid = false
		}

		prevHash = e.Hash
	}

	return chainValid, count, rows.Err()
}

func (a *AuditLog) Count() (int, error) {
	var cnt int
	err := a.db.QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&cnt)
	return cnt, err
}

func (a *AuditLog) ListEvents() ([]Event, error) {
	rows, err := a.db.Query(`SELECT id, timestamp, actor, action, package_name, version, result, reason, meta, previous_hash, hash FROM audit_events ORDER BY id DESC`)
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Actor, &e.Action, &e.PackageName, &e.Version, &e.Result, &e.Reason, &e.Meta, &e.PrevHash, &e.Hash); err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		events = append(events, e)
	}
	return events, rows.Err()
}
