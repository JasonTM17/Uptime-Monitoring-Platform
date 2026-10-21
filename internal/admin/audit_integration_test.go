//go:build integration

package admin_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/admin"
)

func seedUser(t *testing.T, conn *pgx.Conn, prefix string) uuid.UUID {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	uid := uuid.New()
	if _, err := conn.Exec(ctx, `
		INSERT INTO uptime.users (id, email, password_hash)
		VALUES ($1,$2,'x')`, uid, prefix+"-"+uid.String()[:8]+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return uid
}

// TestAuditAtomicity: the business mutation and its audit share one
// transaction — a rollback leaves no audit, and an append failure
// rolls back the mutation.
func TestAuditAtomicity(t *testing.T) {
	conn := connect(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	actor := seedUser(t, conn, "audit")

	t.Run("rollback leaves no audit", func(t *testing.T) {
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		ev := admin.AuditEvent{
			ActorID:   uuid.NullUUID{UUID: actor, Valid: true},
			ActorKind: admin.ActorUser, Action: "user.suspend",
			SubjectType: "user", SubjectID: actor.String(),
			Reason: "test", Outcome: admin.OutcomeSuccess,
			RequestID: "r-rollback",
		}
		if err := admin.AppendAudit(ctx, tx, ev); err != nil {
			t.Fatalf("append: %v", err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		var n int
		if err := conn.QueryRow(ctx, `
			SELECT count(*) FROM uptime.audit_events
			WHERE request_id='r-rollback'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("rolled-back audit persisted: %d", n)
		}
	})

	t.Run("append failure rolls back mutation", func(t *testing.T) {
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		// Business mutation: bump the target's version.
		if _, err := tx.Exec(ctx, `
			UPDATE uptime.users SET version=version+1 WHERE id=$1`,
			actor); err != nil {
			t.Fatal(err)
		}
		bad := admin.AuditEvent{
			ActorID:   uuid.NullUUID{UUID: actor, Valid: true},
			ActorKind: admin.ActorUser, Action: "user.suspend",
			SubjectType: "user", SubjectID: actor.String(),
			Reason:  "", // invalid: empty reason
			Outcome: admin.OutcomeSuccess, RequestID: "r-bad",
		}
		if err := admin.AppendAudit(ctx, tx, bad); err == nil {
			t.Fatal("invalid audit accepted")
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		var v int64
		if err := conn.QueryRow(ctx,
			`SELECT version FROM uptime.users WHERE id=$1`, actor).Scan(&v); err != nil {
			t.Fatal(err)
		}
		if v != 1 {
			t.Fatalf("mutation persisted despite audit failure: version=%d", v)
		}
	})

	t.Run("commit persists audit with correlation", func(t *testing.T) {
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE uptime.users SET version=version+1 WHERE id=$1`,
			actor); err != nil {
			t.Fatal(err)
		}
		diff := admin.RedactAuditDiff(map[string]any{
			"version":       map[string]any{"before": 1, "after": 2},
			"session_token": "leak-me",
		})
		ev := admin.AuditEvent{
			ActorID:   uuid.NullUUID{UUID: actor, Valid: true},
			ActorKind: admin.ActorUser, Action: "user.suspend",
			SubjectType: "user", SubjectID: actor.String(),
			Reason: "abuse report", Outcome: admin.OutcomeSuccess,
			Diff: diff, RequestID: "r-commit",
		}
		if err := admin.AppendAudit(ctx, tx, ev); err != nil {
			t.Fatalf("append: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		var outcome, action, raw string
		err = conn.QueryRow(ctx, `
			SELECT outcome, action, safe_diff::text FROM uptime.audit_events
			WHERE request_id='r-commit'`).Scan(&outcome, &action, &raw)
		if err != nil {
			t.Fatalf("readback: %v", err)
		}
		if outcome != admin.OutcomeSuccess || action != "user.suspend" {
			t.Fatalf("audit fields %s/%s", outcome, action)
		}
		if strings.Contains(raw, "leak-me") {
			t.Fatalf("secret survived into audit: %s", raw)
		}
	})

	t.Run("CLI actor has no actor_id", func(t *testing.T) {
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		ev := admin.AuditEvent{
			ActorKind: admin.ActorCLI, Action: "admin.recover",
			SubjectType: "user", SubjectID: actor.String(),
			Reason: "maintenance", Outcome: admin.OutcomeSuccess,
			RequestID: "r-cli",
		}
		if err := admin.AppendAudit(ctx, tx, ev); err != nil {
			t.Fatalf("cli append: %v", err)
		}
	})
}

// TestAuditPrivileges proves the application role can append and read
// but never update or delete — the append-only boundary is enforced
// by the database, not by service discipline.
func TestAuditPrivileges(t *testing.T) {
	conn := connect(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Ensure the app role exists (operator-bootstrap equivalent on the
	// disposable DB) and holds exactly the migration's grants.
	if _, err := conn.Exec(ctx, `
		DO $$ BEGIN
		  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='uptime_app') THEN
		    CREATE ROLE uptime_app NOLOGIN;
		  END IF;
		END $$;
		GRANT USAGE ON SCHEMA uptime TO uptime_app;
		REVOKE UPDATE, DELETE, TRUNCATE ON uptime.audit_events FROM uptime_app;
		GRANT SELECT, INSERT ON uptime.audit_events TO uptime_app;`); err != nil {
		t.Fatalf("role fixture: %v", err)
	}
	// Seed one row as owner so UPDATE/DELETE have a target.
	actor := seedUser(t, conn, "audit-role")
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ev := admin.AuditEvent{
		ActorID:   uuid.NullUUID{UUID: actor, Valid: true},
		ActorKind: admin.ActorUser, Action: "user.suspend",
		SubjectType: "user", SubjectID: actor.String(),
		Reason: "x", Outcome: admin.OutcomeSuccess, RequestID: "r-priv",
	}
	if err := admin.AppendAudit(ctx, tx, ev); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	if _, err := conn.Exec(ctx, `SET ROLE uptime_app`); err != nil {
		t.Fatalf("set role: %v", err)
	}
	defer conn.Exec(context.Background(), `RESET ROLE`)

	var n int
	if err := conn.QueryRow(ctx,
		`SELECT count(*) FROM uptime.audit_events`).Scan(&n); err != nil {
		t.Fatalf("app role cannot SELECT: %v", err)
	}
	if n == 0 {
		t.Fatal("app role sees zero audit rows")
	}

	_, err = conn.Exec(ctx, `
		UPDATE uptime.audit_events SET reason='tampered'
		WHERE request_id='r-priv'`)
	if !isPGError(err, "42501") {
		t.Fatalf("UPDATE must be denied (42501), got %v", err)
	}
	_, err = conn.Exec(ctx,
		`DELETE FROM uptime.audit_events WHERE request_id='r-priv'`)
	if !isPGError(err, "42501") {
		t.Fatalf("DELETE must be denied (42501), got %v", err)
	}

	// INSERT stays allowed (fresh tx — aborted statements poisoned the
	// last implicit transaction context? pgx autocommits each Exec;
	// errors leave no transaction, so this is clean).
	_, err = conn.Exec(ctx, `
		INSERT INTO uptime.audit_events
		  (id, actor_id, actor_kind, action, subject_type, subject_id,
		   reason, outcome, safe_diff, request_id)
		VALUES ($1,NULL,'SYSTEM','sys','user','t','r','SUCCESS','{}','r-app')`,
		uuid.New())
	if err != nil {
		t.Fatalf("app role INSERT denied: %v", err)
	}
}
