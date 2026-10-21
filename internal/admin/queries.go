package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrUnavailable marks a dependency outage on the read path —
// the handler maps it to 503, distinct from a healthy zero.
var ErrUnavailable = errors.New("dependency unavailable")

// ErrCursor rejects a malformed or filter-mismatched cursor.
var ErrCursor = errors.New("invalid or mismatched cursor")

// keyset is the cursor payload: the last seen sort key plus a hash
// binding the filter set — a cursor minted under different filters
// is rejected, never silently applied.
type keyset struct {
	Key   time.Time `json:"k"`
	ID    uuid.UUID `json:"i"`
	FHash uint64    `json:"f"`
}

func filterHash(parts ...string) uint64 {
	h := fnv.New64a()
	for _, p := range parts {
		_, _ = h.Write([]byte(p))
		_, _ = h.Write([]byte{0})
	}
	return h.Sum64()
}

func encodeCursor(k keyset) string {
	raw, _ := json.Marshal(k)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeCursor(raw string, fhash uint64) (keyset, error) {
	var k keyset
	if raw == "" {
		return k, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || json.Unmarshal(b, &k) != nil || k.FHash != fhash {
		return keyset{}, ErrCursor
	}
	return k, nil
}

// clampLimit bounds every list page.
func clampLimit(n int) int {
	if n <= 0 || n > 100 {
		return 50
	}
	return n
}

// redactTargetHost keeps scheme+host of a monitor URL — path and
// query may carry secrets and are never returned on admin surfaces.
func redactTargetHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "redacted"
	}
	return u.Scheme + "://" + u.Host
}

// Freshness is the explicit tri-state for dependency evidence:
// "fresh" | "stale" | "absent" — a missing heartbeat is never
// reported as healthy.
func Freshness(at *time.Time, staleAfter time.Duration, now time.Time) string {
	if at == nil {
		return "absent"
	}
	if now.Sub(*at) > staleAfter {
		return "stale"
	}
	return "fresh"
}

// OverviewDTO is the platform:read pulse — counts and freshness,
// never raw metrics or provider data.
type OverviewDTO struct {
	Users struct {
		Total    int `json:"total"`
		Active   int `json:"active"`
		Disabled int `json:"disabled"`
	} `json:"users"`
	Monitors struct {
		Total  int `json:"total"`
		Paused int `json:"paused"`
		Up     int `json:"up"`
		Down   int `json:"down"`
	} `json:"monitors"`
	Sessions struct {
		Live int `json:"live"`
	} `json:"sessions"`
	Incidents struct {
		Open int `json:"open"`
	} `json:"incidents"`
	Outbox struct {
		Pending int `json:"pending"`
		Leased  int `json:"leased"`
		Dead    int `json:"dead"`
	} `json:"outbox"`
	Engine struct {
		Epoch         int64      `json:"epoch"`
		HeartbeatAt   *time.Time `json:"heartbeat_at"`
		Freshness     string     `json:"freshness"`
		StaleAfterSec int        `json:"stale_after_seconds"`
	} `json:"engine"`
	Database struct {
		Reachable bool `json:"reachable"`
	} `json:"database"`
}

// Overview aggregates the bounded platform pulse in one read
// transaction — a zero count is honest; absence of engine evidence
// is reported as "absent", not "healthy".
func Overview(ctx context.Context, conn Beginner,
	actor ActorRef, now time.Time) (OverviewDTO, error) {
	var out OverviewDTO
	out.Engine.StaleAfterSec = 30
	err := AuthorizeRead(ctx, conn, actor, "platform:read", now,
		func(tx pgx.Tx, _ map[string]bool) error {
			if err := tx.QueryRow(ctx, `
				SELECT count(*),
				  count(*) FILTER (WHERE status='ACTIVE'),
				  count(*) FILTER (WHERE status='DISABLED')
				FROM uptime.users`).Scan(&out.Users.Total,
				&out.Users.Active, &out.Users.Disabled); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `
				SELECT count(*) FILTER (WHERE deleted_at IS NULL),
				  count(*) FILTER (WHERE deleted_at IS NULL AND is_paused),
				  count(*) FILTER (WHERE deleted_at IS NULL AND health='UP'),
				  count(*) FILTER (WHERE deleted_at IS NULL AND health='DOWN')
				FROM uptime.monitors`).Scan(&out.Monitors.Total,
				&out.Monitors.Paused, &out.Monitors.Up, &out.Monitors.Down); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `
				SELECT count(*) FROM uptime.sessions
				WHERE revoked_at IS NULL AND expires_at>now()`).
				Scan(&out.Sessions.Live); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `
				SELECT count(*) FROM uptime.incidents
				WHERE resolved_at IS NULL`).Scan(&out.Incidents.Open); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `
				SELECT count(*) FILTER (WHERE state='PENDING'),
				  count(*) FILTER (WHERE state='LEASED'),
				  count(*) FILTER (WHERE state='DEAD')
				FROM uptime.notification_outbox`).Scan(&out.Outbox.Pending,
				&out.Outbox.Leased, &out.Outbox.Dead); err != nil {
				return err
			}
			var epoch *int64
			var hb *time.Time
			err := tx.QueryRow(ctx, `
				SELECT epoch, heartbeat_at FROM uptime.engine_control WHERE id=1`).
				Scan(&epoch, &hb)
			switch {
			case errors.Is(err, pgx.ErrNoRows):
				out.Engine.Freshness = "absent"
			case err != nil:
				return err
			default:
				if epoch != nil {
					out.Engine.Epoch = *epoch
				}
				out.Engine.HeartbeatAt = hb
				out.Engine.Freshness = Freshness(hb, 30*time.Second, now)
			}
			out.Database.Reachable = true
			return nil
		})
	if err != nil && isConnError(err) {
		return out, ErrUnavailable
	}
	return out, err
}

func isConnError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "connection") ||
		strings.Contains(msg, "pool is closed") ||
		strings.Contains(msg, "dial") ||
		strings.Contains(msg, "broken pipe")
}

// UserRow is the users:read projection — no password hash, TOTP
// material, or session tokens exist in this shape at all.
type UserRow struct {
	ID           uuid.UUID  `json:"id"`
	Email        string     `json:"email"`
	DisplayName  string     `json:"display_name"`
	Status       string     `json:"status"`
	MonitorLimit int        `json:"monitor_limit"`
	MonitorsLive int        `json:"monitors_live"`
	SessionsLive int        `json:"sessions_live"`
	Roles        []string   `json:"roles"`
	CreatedAt    time.Time  `json:"created_at"`
	DisabledAt   *time.Time `json:"disabled_at"`
}

// UsersFilter is the bounded users:read filter set.
type UsersFilter struct {
	Q      string // bounded email substring
	Status string // "" | ACTIVE | DISABLED
	RoleID string // optional role UUID
	Limit  int
	Cursor string
}

// ListUsers pages the user inventory under users:read — keyset
// pagination on (created_at, id) DESC bound to the filter set.
func ListUsers(ctx context.Context, conn Beginner, actor ActorRef,
	f UsersFilter, now time.Time) ([]UserRow, string, error) {
	var rows []UserRow
	var next string
	fh := filterHash(f.Q, f.Status, f.RoleID)
	ks, err := decodeCursor(f.Cursor, fh)
	if err != nil {
		return nil, "", err
	}
	if f.Status != "" && f.Status != "ACTIVE" && f.Status != "DISABLED" {
		return nil, "", ErrValidation
	}
	if len(f.Q) > 120 {
		return nil, "", ErrValidation
	}
	if f.RoleID != "" {
		if _, err := uuid.Parse(f.RoleID); err != nil {
			return nil, "", ErrValidation
		}
	}
	limit := clampLimit(f.Limit)
	err = AuthorizeRead(ctx, conn, actor, "users:read", now,
		func(tx pgx.Tx, _ map[string]bool) error {
			q := `
				SELECT u.id,u.email,COALESCE(u.display_name,''),u.status,
				  u.monitor_limit,u.created_at,u.disabled_at,
				  (SELECT count(*) FROM uptime.monitors m
				    WHERE m.user_id=u.id AND m.deleted_at IS NULL),
				  (SELECT count(*) FROM uptime.sessions s
				    WHERE s.user_id=u.id AND s.revoked_at IS NULL
				      AND s.expires_at>now()),
				  COALESCE((SELECT array_agg(r.code ORDER BY r.code)
				    FROM uptime.user_roles ur
				    JOIN uptime.roles r ON r.id=ur.role_id
				    WHERE ur.user_id=u.id), '{}')
				FROM uptime.users u
				WHERE ($1='' OR u.email ILIKE '%'||$1||'%')
				  AND ($2='' OR u.status=$2)
				  AND ($3='' OR EXISTS(SELECT 1 FROM uptime.user_roles ur
				    WHERE ur.user_id=u.id AND ur.role_id=$3::uuid))`
			args := []any{f.Q, f.Status, f.RoleID}
			if !ks.Key.IsZero() {
				q += ` AND (u.created_at,u.id) < ($4,$5)`
				args = append(args, ks.Key, ks.ID)
			}
			q += ` ORDER BY u.created_at DESC, u.id DESC LIMIT ` +
				fmt.Sprint(limit+1)
			rs, err := tx.Query(ctx, q, args...)
			if err != nil {
				return err
			}
			defer rs.Close()
			for rs.Next() {
				var u UserRow
				var roles []string
				if err := rs.Scan(&u.ID, &u.Email, &u.DisplayName,
					&u.Status, &u.MonitorLimit, &u.CreatedAt,
					&u.DisabledAt, &u.MonitorsLive, &u.SessionsLive,
					&roles); err != nil {
					return err
				}
				u.Roles = roles
				rows = append(rows, u)
			}
			return rs.Err()
		})
	if len(rows) > limit {
		last := rows[limit-1]
		rows = rows[:limit]
		next = encodeCursor(keyset{Key: last.CreatedAt, ID: last.ID, FHash: fh})
	}
	if err != nil && isConnError(err) {
		return nil, "", ErrUnavailable
	}
	return rows, next, err
}

// MonitorRow is the monitors:global:read projection — the target
// URL is reduced to scheme+host; path/query secrets never leak.
type MonitorRow struct {
	ID            uuid.UUID  `json:"id"`
	OwnerID       uuid.UUID  `json:"owner_id"`
	Name          string     `json:"name"`
	Target        string     `json:"target"`
	Health        string     `json:"health"`
	IsPaused      bool       `json:"is_paused"`
	Generation    int64      `json:"generation"`
	LastCheckedAt *time.Time `json:"last_checked_at"`
	NextCheckAt   time.Time  `json:"next_check_at"`
	CreatedAt     time.Time  `json:"created_at"`
}

// MonitorsFilter bounds the global monitor page.
type MonitorsFilter struct {
	Owner  string // optional owner UUID
	Paused string // "" | "true" | "false"
	Health string // "" | UP | DOWN | UNKNOWN
	Limit  int
	Cursor string
}

// ListGlobalMonitors pages the redacted monitor inventory under
// monitors:global:read — same keyset+filter binding as users.
func ListGlobalMonitors(ctx context.Context, conn Beginner,
	actor ActorRef, f MonitorsFilter, now time.Time) ([]MonitorRow, string, error) {
	var rows []MonitorRow
	var next string
	fh := filterHash(f.Owner, f.Paused, f.Health)
	ks, err := decodeCursor(f.Cursor, fh)
	if err != nil {
		return nil, "", err
	}
	if f.Paused != "" && f.Paused != "true" && f.Paused != "false" {
		return nil, "", ErrValidation
	}
	if f.Health != "" && f.Health != "UP" && f.Health != "DOWN" &&
		f.Health != "UNKNOWN" {
		return nil, "", ErrValidation
	}
	if f.Owner != "" {
		if _, err := uuid.Parse(f.Owner); err != nil {
			return nil, "", ErrValidation
		}
	}
	limit := clampLimit(f.Limit)
	err = AuthorizeRead(ctx, conn, actor, "monitors:global:read", now,
		func(tx pgx.Tx, _ map[string]bool) error {
			q := `
				SELECT id,user_id,name,target_url,health,is_paused,
				  generation,last_checked_at,next_check_at,created_at
				FROM uptime.monitors
				WHERE deleted_at IS NULL
				  AND ($1='' OR user_id=$1::uuid)
				  AND ($2='' OR is_paused=$2::boolean)
				  AND ($3='' OR health=$3)`
			args := []any{f.Owner, f.Paused, f.Health}
			if !ks.Key.IsZero() {
				q += ` AND (created_at,id) < ($4,$5)`
				args = append(args, ks.Key, ks.ID)
			}
			q += ` ORDER BY created_at DESC, id DESC LIMIT ` +
				fmt.Sprint(limit+1)
			rs, err := tx.Query(ctx, q, args...)
			if err != nil {
				return err
			}
			defer rs.Close()
			for rs.Next() {
				var m MonitorRow
				var raw string
				if err := rs.Scan(&m.ID, &m.OwnerID, &m.Name, &raw,
					&m.Health, &m.IsPaused, &m.Generation,
					&m.LastCheckedAt, &m.NextCheckAt, &m.CreatedAt); err != nil {
					return err
				}
				m.Target = redactTargetHost(raw)
				rows = append(rows, m)
			}
			return rs.Err()
		})
	if len(rows) > limit {
		last := rows[limit-1]
		rows = rows[:limit]
		next = encodeCursor(keyset{Key: last.CreatedAt, ID: last.ID, FHash: fh})
	}
	if err != nil && isConnError(err) {
		return nil, "", ErrUnavailable
	}
	return rows, next, err
}

// OperationsDTO is the operations:read health projection —
// engine freshness, queue depth, outbox backlog age and rollup
// lag. No DSNs, pool internals, or raw provider errors.
type OperationsDTO struct {
	Engine struct {
		Epoch         int64      `json:"epoch"`
		OwnerInstance *string    `json:"owner_instance"`
		HeartbeatAt   *time.Time `json:"heartbeat_at"`
		Freshness     string     `json:"freshness"`
		StaleAfterSec int        `json:"stale_after_seconds"`
	} `json:"engine"`
	Runs struct {
		Reserved int `json:"reserved"`
		Running  int `json:"running"`
	} `json:"runs"`
	Outbox struct {
		Pending          int        `json:"pending"`
		Leased           int        `json:"leased"`
		Dead             int        `json:"dead"`
		OldestPending    *time.Time `json:"oldest_pending"`
		OldestAgeSeconds *int64     `json:"oldest_age_seconds"`
	} `json:"outbox"`
	Rollup struct {
		LastBucket *time.Time `json:"last_bucket"`
		Freshness  string     `json:"freshness"`
	} `json:"rollup"`
}

// OperationsSnapshot reads the bounded ops surface under
// operations:read — explicit freshness everywhere, never raw metrics.
func OperationsSnapshot(ctx context.Context, conn Beginner,
	actor ActorRef, now time.Time) (OperationsDTO, error) {
	var out OperationsDTO
	out.Engine.StaleAfterSec = 30
	err := AuthorizeRead(ctx, conn, actor, "operations:read", now,
		func(tx pgx.Tx, _ map[string]bool) error {
			var epoch *int64
			var owner *uuid.UUID
			var hb *time.Time
			err := tx.QueryRow(ctx, `
				SELECT epoch, owner_instance, heartbeat_at
				FROM uptime.engine_control WHERE id=1`).Scan(&epoch, &owner, &hb)
			switch {
			case errors.Is(err, pgx.ErrNoRows):
				out.Engine.Freshness = "absent"
			case err != nil:
				return err
			default:
				if epoch != nil {
					out.Engine.Epoch = *epoch
				}
				if owner != nil {
					s := owner.String()
					out.Engine.OwnerInstance = &s
				}
				out.Engine.HeartbeatAt = hb
				out.Engine.Freshness = Freshness(hb, 30*time.Second, now)
			}
			if err := tx.QueryRow(ctx, `
				SELECT count(*) FILTER (WHERE status='RESERVED'),
				  count(*) FILTER (WHERE status='RUNNING')
				FROM uptime.check_runs`).Scan(&out.Runs.Reserved,
				&out.Runs.Running); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `
				SELECT count(*) FILTER (WHERE state='PENDING'),
				  count(*) FILTER (WHERE state='LEASED'),
				  count(*) FILTER (WHERE state='DEAD'),
				  min(next_attempt_at) FILTER (WHERE state='PENDING')
				FROM uptime.notification_outbox`).Scan(&out.Outbox.Pending,
				&out.Outbox.Leased, &out.Outbox.Dead,
				&out.Outbox.OldestPending); err != nil {
				return err
			}
			if out.Outbox.OldestPending != nil {
				age := int64(now.Sub(*out.Outbox.OldestPending).Seconds())
				out.Outbox.OldestAgeSeconds = &age
			}
			var bucket *time.Time
			if err := tx.QueryRow(ctx, `
				SELECT max(bucket_start) FROM uptime.hourly_stats`).
				Scan(&bucket); err != nil {
				return err
			}
			out.Rollup.LastBucket = bucket
			// Rollup evidence older than two hours is stale; missing
			// entirely is absent (a fresh deployment is not "healthy").
			out.Rollup.Freshness = Freshness(bucket, 2*time.Hour, now)
			return nil
		})
	if err != nil && isConnError(err) {
		return out, ErrUnavailable
	}
	return out, err
}

// OutboxRow is the deliveries:read projection — lifecycle and
// counters only; payload and destination never leave the store.
type OutboxRow struct {
	ID            uuid.UUID  `json:"id"`
	MonitorID     uuid.UUID  `json:"monitor_id"`
	IncidentID    *uuid.UUID `json:"incident_id"`
	EventKind     string     `json:"event_kind"`
	State         string     `json:"state"`
	Attempts      int        `json:"attempts"`
	NextAttemptAt *time.Time `json:"next_attempt_at"`
	LastErrorCode *string    `json:"last_error_code"`
	CreatedAt     time.Time  `json:"created_at"`
	Version       int64      `json:"version"`
}

// OutboxFilter bounds the deliveries:read page.
type OutboxFilter struct {
	State  string // "" | PENDING|LEASED|SENT|DEAD|SUPPRESSED
	Limit  int
	Cursor string
}

// ListOutbox pages the outbox under deliveries:read.
func ListOutbox(ctx context.Context, conn Beginner, actor ActorRef,
	f OutboxFilter, now time.Time) ([]OutboxRow, string, error) {
	var rows []OutboxRow
	var next string
	fh := filterHash(f.State)
	ks, err := decodeCursor(f.Cursor, fh)
	if err != nil {
		return nil, "", err
	}
	switch f.State {
	case "", "PENDING", "LEASED", "SENT", "DEAD", "SUPPRESSED":
	default:
		return nil, "", ErrValidation
	}
	limit := clampLimit(f.Limit)
	err = AuthorizeRead(ctx, conn, actor, "deliveries:read", now,
		func(tx pgx.Tx, _ map[string]bool) error {
			q := `
				SELECT id,monitor_id,incident_id,event_kind,state,attempts,
				  next_attempt_at,last_error_code,created_at,version
				FROM uptime.notification_outbox
				WHERE ($1='' OR state=$1)`
			args := []any{f.State}
			if !ks.Key.IsZero() {
				q += ` AND (created_at,id) < ($2,$3)`
				args = append(args, ks.Key, ks.ID)
			}
			q += ` ORDER BY created_at DESC, id DESC LIMIT ` +
				fmt.Sprint(limit+1)
			rs, err := tx.Query(ctx, q, args...)
			if err != nil {
				return err
			}
			defer rs.Close()
			for rs.Next() {
				var o OutboxRow
				if err := rs.Scan(&o.ID, &o.MonitorID, &o.IncidentID,
					&o.EventKind, &o.State, &o.Attempts, &o.NextAttemptAt,
					&o.LastErrorCode, &o.CreatedAt, &o.Version); err != nil {
					return err
				}
				rows = append(rows, o)
			}
			return rs.Err()
		})
	if len(rows) > limit {
		last := rows[limit-1]
		rows = rows[:limit]
		next = encodeCursor(keyset{Key: last.CreatedAt, ID: last.ID, FHash: fh})
	}
	if err != nil && isConnError(err) {
		return nil, "", ErrUnavailable
	}
	return rows, next, err
}

// AuditRow is the audit:read projection — the diff column is already
// redacted at write time; the projection adds no new sensitive data.
type AuditRow struct {
	ID          uuid.UUID       `json:"id"`
	ActorID     *uuid.UUID      `json:"actor_id"`
	ActorKind   string          `json:"actor_kind"`
	Action      string          `json:"action"`
	SubjectType string          `json:"subject_type"`
	SubjectID   string          `json:"subject_id"`
	Reason      string          `json:"reason"`
	Outcome     string          `json:"outcome"`
	Diff        json.RawMessage `json:"diff"`
	RequestID   string          `json:"request_id"`
	CreatedAt   time.Time       `json:"created_at"`
}

// AuditFilter bounds the audit:read page — the time window is
// capped at 90 days so an unbounded scan can never stall the admin.
type AuditFilter struct {
	Action  string // optional action prefix
	Actor   string // optional actor UUID
	Subject string // optional subject_id
	From    string // RFC3339 lower bound
	To      string // RFC3339 upper bound
	Limit   int
	Cursor  string
}

const maxAuditWindow = 90 * 24 * time.Hour

// ListAuditEvents pages the audit log under audit:read — bounded
// filters, bounded window, keyset pagination.
func ListAuditEvents(ctx context.Context, conn Beginner, actor ActorRef,
	f AuditFilter, now time.Time) ([]AuditRow, string, error) {
	var rows []AuditRow
	var next string
	fh := filterHash(f.Action, f.Actor, f.Subject, f.From, f.To)
	ks, err := decodeCursor(f.Cursor, fh)
	if err != nil {
		return nil, "", err
	}
	var from, to *time.Time
	if f.From != "" {
		t, err := time.Parse(time.RFC3339, f.From)
		if err != nil {
			return nil, "", ErrValidation
		}
		from = &t
	}
	if f.To != "" {
		t, err := time.Parse(time.RFC3339, f.To)
		if err != nil {
			return nil, "", ErrValidation
		}
		to = &t
	}
	if from != nil && to != nil && to.Sub(*from) > maxAuditWindow {
		return nil, "", ErrValidation
	}
	if f.Actor != "" {
		if _, err := uuid.Parse(f.Actor); err != nil {
			return nil, "", ErrValidation
		}
	}
	if len(f.Action) > 60 || len(f.Subject) > 80 {
		return nil, "", ErrValidation
	}
	limit := clampLimit(f.Limit)
	err = AuthorizeRead(ctx, conn, actor, "audit:read", now,
		func(tx pgx.Tx, _ map[string]bool) error {
			q := `
				SELECT id,actor_id,actor_kind,action,subject_type,
				  subject_id,reason,outcome,safe_diff,request_id,created_at
				FROM uptime.audit_events
				WHERE ($1='' OR action=$1)
				  AND ($2='' OR actor_id=$2::uuid)
				  AND ($3='' OR subject_id=$3)
				  AND ($4::timestamptz IS NULL OR created_at>=$4)
				  AND ($5::timestamptz IS NULL OR created_at<=$5)`
			args := []any{f.Action, f.Actor, f.Subject, from, to}
			if !ks.Key.IsZero() {
				q += ` AND (created_at,id) < ($6,$7)`
				args = append(args, ks.Key, ks.ID)
			}
			q += ` ORDER BY created_at DESC, id DESC LIMIT ` +
				fmt.Sprint(limit+1)
			rs, err := tx.Query(ctx, q, args...)
			if err != nil {
				return err
			}
			defer rs.Close()
			for rs.Next() {
				var a AuditRow
				if err := rs.Scan(&a.ID, &a.ActorID, &a.ActorKind,
					&a.Action, &a.SubjectType, &a.SubjectID, &a.Reason,
					&a.Outcome, &a.Diff, &a.RequestID, &a.CreatedAt); err != nil {
					return err
				}
				rows = append(rows, a)
			}
			return rs.Err()
		})
	if len(rows) > limit {
		last := rows[limit-1]
		rows = rows[:limit]
		next = encodeCursor(keyset{Key: last.CreatedAt, ID: last.ID, FHash: fh})
	}
	if err != nil && isConnError(err) {
		return nil, "", ErrUnavailable
	}
	return rows, next, err
}

// GetAuditEvent returns one redacted audit row under audit:read —
// 404 for anything outside it.
func GetAuditEvent(ctx context.Context, conn Beginner, actor ActorRef,
	id uuid.UUID, now time.Time) (AuditRow, error) {
	var a AuditRow
	err := AuthorizeRead(ctx, conn, actor, "audit:read", now,
		func(tx pgx.Tx, _ map[string]bool) error {
			return tx.QueryRow(ctx, `
				SELECT id,actor_id,actor_kind,action,subject_type,
				  subject_id,reason,outcome,safe_diff,request_id,created_at
				FROM uptime.audit_events WHERE id=$1`, id).
				Scan(&a.ID, &a.ActorID, &a.ActorKind, &a.Action,
					&a.SubjectType, &a.SubjectID, &a.Reason, &a.Outcome,
					&a.Diff, &a.RequestID, &a.CreatedAt)
		})
	if errors.Is(err, pgx.ErrNoRows) {
		return a, ErrSubjectRevoked
	}
	if err != nil && isConnError(err) {
		return a, ErrUnavailable
	}
	return a, err
}

// UserDetailDTO is the users:read single-account projection —
// account fields plus bounded counts, never password/TOTP/token
// material (those columns are simply not selected).
type UserDetailDTO struct {
	UserRow
	SecurityVersion int64 `json:"security_version"`
	Version         int64 `json:"version"`
}

// GetUser returns one account under users:read — 404 outside.
func GetUser(ctx context.Context, conn Beginner, actor ActorRef,
	id uuid.UUID, now time.Time) (UserDetailDTO, error) {
	var d UserDetailDTO
	err := AuthorizeRead(ctx, conn, actor, "users:read", now,
		func(tx pgx.Tx, _ map[string]bool) error {
			var roles []string
			err := tx.QueryRow(ctx, `
				SELECT u.id,u.email,COALESCE(u.display_name,''),u.status,
				  u.monitor_limit,u.created_at,u.disabled_at,
				  (SELECT count(*) FROM uptime.monitors m
				    WHERE m.user_id=u.id AND m.deleted_at IS NULL),
				  (SELECT count(*) FROM uptime.sessions s
				    WHERE s.user_id=u.id AND s.revoked_at IS NULL
				      AND s.expires_at>now()),
				  COALESCE((SELECT array_agg(r.code ORDER BY r.code)
				    FROM uptime.user_roles ur
				    JOIN uptime.roles r ON r.id=ur.role_id
				    WHERE ur.user_id=u.id), '{}'),
				  u.security_version, u.version
				FROM uptime.users u WHERE u.id=$1`, id).
				Scan(&d.ID, &d.Email, &d.DisplayName, &d.Status,
					&d.MonitorLimit, &d.CreatedAt, &d.DisabledAt,
					&d.MonitorsLive, &d.SessionsLive, &roles,
					&d.SecurityVersion, &d.Version)
			if err != nil {
				return err
			}
			d.Roles = roles
			return nil
		})
	if errors.Is(err, pgx.ErrNoRows) {
		return d, ErrSubjectRevoked
	}
	if err != nil && isConnError(err) {
		return d, ErrUnavailable
	}
	return d, err
}
