// Package testsupport holds restore-drill assertions shared between
// the operator path (scripts/restore-drill.mjs) and the integration
// tests that pin the semantics. The script validates the same manifest
// contract with its own code; this package is the canonical definition.
package testsupport

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// DrillFormat is the manifest format identity — a restore refuses any
// dump whose receipt does not carry it.
const DrillFormat = "uptime-restore-v1"

// BackupManifest is the receipt written next to a dump. Restore must
// validate it before touching the target: wrong format, corrupt JSON,
// or a schema version different from the migration head fails closed.
type BackupManifest struct {
	Format        string    `json:"format"`
	SchemaVersion int64     `json:"schema_version"`
	CreatedAt     time.Time `json:"created_at"`
	SourceDB      string    `json:"source_db"`
	PgDumpVersion string    `json:"pg_dump_version"`
	DumpSHA256    string    `json:"dump_sha256"`
	Tables        int       `json:"tables"`
}

// ErrManifest marks every manifest rejection — corrupt, wrong-format,
// or wrong-version backups all fail closed with the same error class.
var ErrManifest = errors.New("invalid backup manifest")

// ValidateManifest parses and checks a manifest against the expected
// migration head. Rejects corrupt JSON, wrong drill format, missing
// fields, and schema mismatches — never guesses, never falls back.
func ValidateManifest(raw []byte, wantSchema int64) (BackupManifest, error) {
	var m BackupManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return BackupManifest{}, fmt.Errorf("%w: corrupt json", ErrManifest)
	}
	if m.Format != DrillFormat {
		return BackupManifest{}, fmt.Errorf("%w: format %q", ErrManifest, m.Format)
	}
	if m.SchemaVersion != wantSchema {
		return BackupManifest{}, fmt.Errorf("%w: schema %d, want %d",
			ErrManifest, m.SchemaVersion, wantSchema)
	}
	if m.SourceDB == "" || m.CreatedAt.IsZero() || len(m.DumpSHA256) != 64 {
		return BackupManifest{}, fmt.Errorf("%w: missing required fields", ErrManifest)
	}
	return m, nil
}

// CanonicalTables is the ordered uptime-table list every drill receipt
// compares. Counts must match source-for-clone before any semantic
// assertion runs; the script's receipt and the Go tests use the same
// list so one cannot silently drift from the other.
var CanonicalTables = []string{
	"users", "sessions", "quota_budgets", "monitors",
	"notification_channels", "monitor_channels", "engine_control",
	"schedule_segments", "check_runs", "check_results", "incidents",
	"notification_outbox", "hourly_stats", "permissions", "roles",
	"role_permissions", "user_roles", "security_anchor",
	"audit_events", "admin_idempotency",
}
