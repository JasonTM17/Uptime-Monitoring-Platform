//go:build integration

package admin_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/admin"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/monitor"
)

var testCeilings = admin.QuotaCeilings{RetainedOwner: 50, ColumnBound: 10000}

// seedQuotaBudget ensures the singleton budget row exists for the
// test run.
func seedQuotaBudget(t *testing.T, conn *pgx.Conn, global int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := conn.Exec(ctx, `
		INSERT INTO uptime.quota_budgets(id,global_monitor_limit)
		VALUES (1,$1) ON CONFLICT (id) DO UPDATE
		  SET global_monitor_limit=$1`, global); err != nil {
		t.Fatal(err)
	}
}

// seedNMonitors inserts n non-deleted monitors for the owner.
func seedNMonitors(t *testing.T, conn *pgx.Conn, owner uuid.UUID, n int) func() {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var ids []uuid.UUID
	for i := 0; i < n; i++ {
		var id uuid.UUID
		if err := conn.QueryRow(ctx, `
			INSERT INTO uptime.monitors(id,user_id,name,target_url,method,
			  interval_seconds,timeout_seconds,next_check_at)
			VALUES (gen_random_uuid(),$1,$2,'https://x.test','GET',60,5,now())
			RETURNING id`, owner, "q"+uuid.NewString()[:6]).Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	return func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = conn.Exec(c, `DELETE FROM uptime.check_runs WHERE monitor_id=ANY($1)`, ids)
		_, _ = conn.Exec(c, `DELETE FROM uptime.schedule_segments WHERE monitor_id=ANY($1)`, ids)
		_, _ = conn.Exec(c, `DELETE FROM uptime.monitors WHERE id=ANY($1)`, ids)
	}
}

func TestQuotaCeiling(t *testing.T) {
	conn := connect(t)
	actor, cleanup := superActor(t, conn, "c61-ceil")
	defer cleanup()
	subject, subCleanup := plainUser(t, conn, "c61-quota")
	defer subCleanup()
	seedQuotaBudget(t, conn, 100)
	cleanupMon := seedNMonitors(t, conn, subject.UserID, 3)
	defer cleanupMon()

	body := []byte(`{"monitor_limit":2}`)
	ver, _ := userVersion(t, conn, subject.UserID)
	ctx := context.Background()

	t.Run("cap below locked usage is 409 no partial", func(t *testing.T) {
		_, err := admin.SetUserQuota(ctx, conn, testCeilings, actor,
			subject.UserID, admin.QuotaInput{
				MonitorLimit: 2, ExpectedVersion: ver, Reason: "x",
			}, "k-q-1", body, time.Now())
		var qc *admin.QuotaConflict
		if !errors.As(err, &qc) {
			t.Fatalf("want QuotaConflict, got %v", err)
		}
		if qc.Usage != 3 || qc.Requested != 2 {
			t.Fatalf("conflict fields: %+v", qc)
		}
		// No cap change, no version bump, no success audit.
		var limit int
		_ = conn.QueryRow(ctx, `SELECT monitor_limit FROM uptime.users WHERE id=$1`,
			subject.UserID).Scan(&limit)
		if limit == 2 {
			t.Fatal("denied cap still applied")
		}
		ver2, _ := userVersion(t, conn, subject.UserID)
		if ver2 != ver {
			t.Fatalf("denied cap bumped version %d -> %d", ver, ver2)
		}
		var audit int
		_ = conn.QueryRow(ctx, `
			SELECT count(*) FROM uptime.audit_events
			WHERE action='quota.set' AND subject_id=$1`,
			subject.UserID.String()).Scan(&audit)
		if audit != 0 {
			t.Fatalf("denied quota wrote %d success audits", audit)
		}
	})

	t.Run("cap above global ceiling is 409", func(t *testing.T) {
		_, err := admin.SetUserQuota(ctx, conn, testCeilings, actor,
			subject.UserID, admin.QuotaInput{
				MonitorLimit: 101, ExpectedVersion: ver, Reason: "x",
			}, "k-q-2", body, time.Now())
		if !errors.Is(err, admin.ErrStaleEpoch) {
			t.Fatalf("want 409-class error, got %v", err)
		}
	})

	t.Run("cap above retained owner ceiling is 409", func(t *testing.T) {
		_, err := admin.SetUserQuota(ctx, conn,
			admin.QuotaCeilings{RetainedOwner: 60, ColumnBound: 10000},
			actor, subject.UserID, admin.QuotaInput{
				MonitorLimit: 61, ExpectedVersion: ver, Reason: "x",
			}, "k-q-3", body, time.Now())
		if !errors.Is(err, admin.ErrStaleEpoch) {
			t.Fatalf("want 409-class error, got %v", err)
		}
	})

	t.Run("negative and overflow caps are 422", func(t *testing.T) {
		for _, bad := range []int{-1, 10001} {
			_, err := admin.SetUserQuota(ctx, conn, testCeilings, actor,
				subject.UserID, admin.QuotaInput{
					MonitorLimit: bad, ExpectedVersion: ver, Reason: "x",
				}, "k-q-bad"+string(rune('a'+bad&1)), body, time.Now())
			var ve *admin.ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("cap=%d: want ValidationError, got %v", bad, err)
			}
		}
	})

	t.Run("valid cap commits with audit", func(t *testing.T) {
		ver, _ := userVersion(t, conn, subject.UserID)
		res, err := admin.SetUserQuota(ctx, conn, testCeilings, actor,
			subject.UserID, admin.QuotaInput{
				MonitorLimit: 5, ExpectedVersion: ver, Reason: "plan change",
			}, "k-q-4", body, time.Now())
		if err != nil {
			t.Fatalf("set quota: %v", err)
		}
		if res.Response["monitor_limit"] != 5 || res.Response["usage"] != 3 {
			t.Fatalf("unexpected response: %+v", res.Response)
		}
		var audit int
		_ = conn.QueryRow(ctx, `
			SELECT count(*) FROM uptime.audit_events
			WHERE action='quota.set' AND subject_id=$1`,
			subject.UserID.String()).Scan(&audit)
		if audit != 1 {
			t.Fatalf("audit rows=%d", audit)
		}
	})
}

// TestAdminQuotaRace: a lowering SetUserQuota and a concurrent
// monitor create serialize on the same users-row lock — the outcome
// is either create-then-failed-lower or lower-then-failed-create,
// never cap<usage.
func TestAdminQuotaRace(t *testing.T) {
	conn := connect(t)
	conn2 := connect(t)
	conn3 := connect(t)
	actor, cleanup := superActor(t, conn, "c61-race")
	defer cleanup()
	subject, subCleanup := plainUser(t, conn, "c61-racetgt")
	defer subCleanup()
	seedQuotaBudget(t, conn, 100)
	cleanupMon := seedNMonitors(t, conn, subject.UserID, 3)
	defer cleanupMon()
	ctx := context.Background()

	// Raise the cap headroom first so the race is meaningful.
	ver, _ := userVersion(t, conn, subject.UserID)
	if _, err := admin.SetUserQuota(ctx, conn, testCeilings, actor,
		subject.UserID, admin.QuotaInput{
			MonitorLimit: 4, ExpectedVersion: ver, Reason: "seed",
		}, "k-race-0", []byte(`{}`), time.Now()); err != nil {
		t.Fatalf("seed cap: %v", err)
	}

	repo := monitor.NewRepository(nil, 0)
	var wg sync.WaitGroup
	var lowerErr, createErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		ver, _ := userVersion(t, conn2, subject.UserID)
		_, lowerErr = admin.SetUserQuota(ctx, conn2, testCeilings, actor,
			subject.UserID, admin.QuotaInput{
				MonitorLimit: 3, ExpectedVersion: ver, Reason: "lower",
			}, "k-race-1", []byte(`{}`), time.Now())
	}()
	go func() {
		defer wg.Done()
		tx, err := conn3.Begin(ctx)
		if err != nil {
			createErr = err
			return
		}
		defer tx.Rollback(ctx)
		// Mirror CreateMonitorTx's lock order: user row FOR UPDATE
		// (the same row SetUserQuota holds under the anchor).
		var limit int
		var st string
		if err := tx.QueryRow(ctx, `
			SELECT status,monitor_limit FROM uptime.users
			WHERE id=$1 FOR UPDATE`, subject.UserID).Scan(&st, &limit); err != nil {
			createErr = err
			return
		}
		_, createErr = repo.CreateMonitorTx(ctx, tx, subject.UserID, limit,
			monitor.WriteFields{Name: "r", TargetURL: "https://r.test",
				IntervalSeconds: 60, TimeoutSeconds: 5},
			monitor.Caps{RetainedOwner: 50, RetainedGlobal: 100})
		if createErr == nil {
			createErr = tx.Commit(ctx)
		}
	}()
	wg.Wait()

	var usage, capNow int
	_ = conn.QueryRow(ctx, `
		SELECT count(*) FROM uptime.monitors
		WHERE user_id=$1 AND deleted_at IS NULL`, subject.UserID).Scan(&usage)
	_ = conn.QueryRow(ctx, `SELECT monitor_limit FROM uptime.users WHERE id=$1`,
		subject.UserID).Scan(&capNow)
	if capNow < usage {
		t.Fatalf("race produced cap<usage: cap=%d usage=%d (lower=%v create=%v)",
			capNow, usage, lowerErr, createErr)
	}
	// Exactly one winner: create-then-lower-409 or lower-then-create-denied.
	winners := 0
	if createErr == nil {
		winners++
	}
	if lowerErr == nil {
		winners++
	}
	if winners == 2 {
		t.Fatalf("both mutations won: lower=%v create=%v", lowerErr, createErr)
	}
}

func TestAdminRevokeSessions(t *testing.T) {
	conn := connect(t)
	actor, cleanup := superActor(t, conn, "c61-rev")
	defer cleanup()
	subject, subCleanup := plainUser(t, conn, "c61-tgt")
	defer subCleanup()
	ctx := context.Background()
	body := []byte(`{"reason":"lost device"}`)

	ver, secBefore := userVersion(t, conn, subject.UserID)
	res, err := admin.RevokeUserSessions(ctx, conn, actor, subject.UserID,
		admin.RevokeSessionsInput{ExpectedVersion: ver, Reason: "lost device"},
		"k-rev-1", body, time.Now())
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if res.Response["sessions_revoked"] != int64(1) {
		t.Fatalf("revoked=%v, want 1", res.Response["sessions_revoked"])
	}
	var live int
	_ = conn.QueryRow(ctx, `
		SELECT count(*) FROM uptime.sessions
		WHERE user_id=$1 AND revoked_at IS NULL`, subject.UserID).Scan(&live)
	if live != 0 {
		t.Fatalf("%d sessions survived revoke", live)
	}
	_, secAfter := userVersion(t, conn, subject.UserID)
	if secAfter != secBefore+1 {
		t.Fatalf("revoke did not bump epoch: %d -> %d", secBefore, secAfter)
	}

	t.Run("revoked actor cannot run privileged write", func(t *testing.T) {
		// The subject's own session is dead — a privileged recipe under
		// its stale ActorRef must fail the session recheck.
		victim, vCleanup := plainUser(t, conn, "c61-barr")
		defer vCleanup()
		vver, _ := userVersion(t, conn, victim.UserID)
		_, err := admin.RevokeUserSessions(ctx, conn, subject, victim.UserID,
			admin.RevokeSessionsInput{ExpectedVersion: vver, Reason: "x"},
			"k-barr-1", body, time.Now())
		if !errors.Is(err, admin.ErrActorRevoked) {
			t.Fatalf("want ErrActorRevoked, got %v", err)
		}
	})

	t.Run("permission split is honored", func(t *testing.T) {
		// sessions:manage actor (SECURITY_ADMIN) cannot set quota —
		// each capability is checked independently.
		sa, saCleanup := authFixture(t, conn, "c61-seca")
		defer saCleanup()
		ctx2, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := conn.Exec(ctx2, `
			DELETE FROM uptime.user_roles WHERE user_id=$1`, sa.UserID); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Exec(ctx2, `
			INSERT INTO uptime.user_roles (user_id, role_id)
			VALUES ($1,'00000000-0000-4000-8000-000000000004')`,
			sa.UserID); err != nil {
			t.Fatal(err)
		}
		stampReauth(t, conn, sa.SessionID, 0)
		v, _ := userVersion(t, conn, subject.UserID)
		_, err := admin.SetUserQuota(ctx, conn, testCeilings, sa,
			subject.UserID, admin.QuotaInput{
				MonitorLimit: 9, ExpectedVersion: v, Reason: "x",
			}, "k-split-1", body, time.Now())
		if !errors.Is(err, admin.ErrForbidden) {
			t.Fatalf("want ErrForbidden for quota via sessions:manage, got %v", err)
		}
		// But the same actor CAN revoke sessions.
		v, _ = userVersion(t, conn, subject.UserID)
		res, err := admin.RevokeUserSessions(ctx, conn, sa, subject.UserID,
			admin.RevokeSessionsInput{ExpectedVersion: v, Reason: "x"},
			"k-split-2", body, time.Now())
		if err != nil {
			t.Fatalf("sessions:manage actor denied revoke: %v", err)
		}
		if res.Status != 200 {
			t.Fatalf("revoke status=%d", res.Status)
		}
	})
}
