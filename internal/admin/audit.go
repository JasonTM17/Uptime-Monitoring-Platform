package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Actor kinds allowed by the audit schema. CLI covers the operator
// recovery tool (nullable actor_id); SYSTEM covers unattended
// maintenance.
const (
	ActorUser   = "USER"
	ActorCLI    = "CLI"
	ActorSystem = "SYSTEM"
)

// Audit outcomes allowed by the schema. A denied attempt is recorded
// in its own transaction when the business transaction rolled back —
// never report SUCCESS for an unconfirmed commit.
const (
	OutcomeSuccess = "SUCCESS"
	OutcomeDenied  = "DENIED"
	OutcomeFailure = "FAILURE"
)

// AuditEvent is one append-only record. Diff is the redacted
// before/after payload; it must already have passed RedactAuditDiff.
type AuditEvent struct {
	ActorID     uuid.NullUUID
	ActorKind   string
	Action      string
	SubjectType string
	SubjectID   string
	Reason      string
	Outcome     string
	Diff        map[string]any
	RequestID   string
}

// Audit bounds.
const (
	maxAuditReason  = 500
	maxAuditField   = 120
	maxAuditDiffLen = 8192
	maxAuditDepth   = 4
)

var ErrAuditInvalid = errors.New("invalid audit event")

// AppendAudit inserts one audit row inside the caller's business
// transaction: the mutation and its audit commit or roll back
// together — an append failure aborts the mutation, and a rolled-back
// mutation leaves no SUCCESS audit.
func AppendAudit(ctx context.Context, tx pgx.Tx, ev AuditEvent) error {
	if !validAuditKind(ev.ActorKind) || !validAuditOutcome(ev.Outcome) {
		return fmt.Errorf("%w: kind/outcome", ErrAuditInvalid)
	}
	if ev.Action == "" || len(ev.Action) > maxAuditField ||
		ev.SubjectType == "" || len(ev.SubjectType) > maxAuditField ||
		len(ev.Reason) == 0 || len(ev.Reason) > maxAuditReason ||
		len(ev.RequestID) == 0 || len(ev.RequestID) > maxAuditField {
		return fmt.Errorf("%w: bounded fields", ErrAuditInvalid)
	}
	if ev.ActorKind == ActorUser && !ev.ActorID.Valid {
		return fmt.Errorf("%w: user actor needs actor_id", ErrAuditInvalid)
	}
	diff := ev.Diff
	if diff == nil {
		diff = map[string]any{}
	}
	raw, err := json.Marshal(diff)
	if err != nil {
		return fmt.Errorf("%w: diff marshal: %v", ErrAuditInvalid, err)
	}
	if len(raw) > maxAuditDiffLen || auditDepth(diff, 1) > maxAuditDepth {
		return fmt.Errorf("%w: diff bounds", ErrAuditInvalid)
	}
	var actor any
	if ev.ActorID.Valid {
		actor = ev.ActorID.UUID
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO uptime.audit_events
		  (id, actor_id, actor_kind, action, subject_type, subject_id,
		   reason, outcome, safe_diff, request_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10)`,
		uuid.New(), actor, ev.ActorKind, ev.Action, ev.SubjectType,
		ev.SubjectID, ev.Reason, ev.Outcome, string(raw), ev.RequestID)
	return err
}

func validAuditKind(k string) bool {
	return k == ActorUser || k == ActorCLI || k == ActorSystem
}

func validAuditOutcome(o string) bool {
	return o == OutcomeSuccess || o == OutcomeDenied || o == OutcomeFailure
}

func auditDepth(v any, depth int) int {
	best := depth
	switch t := v.(type) {
	case map[string]any:
		for _, child := range t {
			if d := auditDepth(child, depth+1); d > best {
				best = d
			}
		}
	case []any:
		for _, child := range t {
			if d := auditDepth(child, depth+1); d > best {
				best = d
			}
		}
	}
	return best
}

// redactedValue replaces any secret-bearing field.
const redactedValue = "[REDACTED]"

// secretKeys matches (case-insensitive substring) field names that
// may never enter the audit payload. Over-redaction on a bounded
// metadata field is acceptable; a leak is not.
var secretKeys = []string{
	"password", "passwd", "token", "secret", "api_key", "apikey",
	"private_key", "ciphertext", "encrypted", "destination", "bot",
	"csrf", "totp", "seed", "authorization", "cookie",
	"credential", "dsn", "connection_string", "hash", "salt",
}

// RedactAuditDiff returns a deep copy of diff with every
// secret-keyed value replaced by the redaction marker. Safe fields —
// names, statuses, versions, counts, reasons — pass through.
// Applied before AppendAudit so a caller cannot accidentally record
// raw input, tokens, ciphertext or provider payloads.
func RedactAuditDiff(diff map[string]any) map[string]any {
	out := make(map[string]any, len(diff))
	for k, v := range diff {
		if isSecretKey(k) {
			out[k] = redactedValue
			continue
		}
		out[k] = redactValue(v)
	}
	return out
}

func redactValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		return RedactAuditDiff(t)
	case []any:
		out := make([]any, len(t))
		for i, child := range t {
			out[i] = redactValue(child)
		}
		return out
	default:
		return v
	}
}

func isSecretKey(key string) bool {
	k := strings.ToLower(key)
	for _, s := range secretKeys {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}
