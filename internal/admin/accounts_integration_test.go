//go:build integration

package admin_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/admin"
)

// seedMonitorWithSegment creates a non-paused monitor with an open
// segment for the owner — the smallest fixture the suspend path must
// close and fence.
func seedMonitorWithSegment(t *testing.T, conn *pgx.Conn,
	owner uuid.UUID) (monID, segID uuid.UUID, gen int64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := conn.Exec(ctx, `
		INSERT INTO uptime.quota_budgets(id,global_monitor_limit)
		VALUES (1,1000) ON CONFLICT (id) DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `
		INSERT INTO uptime.monitors(id,user_id,name,target_url,method,
		  interval_seconds,timeout_seconds,next_check_at)
		VALUES (gen_random_uuid(),$1,'m','https://x.test','GET',60,5,
		  now()+interval '1 minute') RETURNING id, generation`,
		owner).Scan(&monID, &gen); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `
		INSERT INTO uptime.schedule_segments(id,monitor_id,generation,
		  starts_at,interval_seconds)
		VALUES (gen_random_uuid(),$1,$2,now()-interval '1 hour',60)
		RETURNING id`, monID, gen).Scan(&segID); err != nil {
		t.Fatal(err)
	}
	return monID, segID, gen
}

func TestAccountSuspension(t *testing.T) {
	conn := connect(t)
	actor, cleanup := superActor(t, conn, "c60-sus")
	defer cleanup()
	subject, subCleanup := plainUser(t, conn, "c60-tgt")
	defer subCleanup()
	monID, segID, gen := seedMonitorWithSegment(t, conn, subject.UserID)
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.Exec(c, `DELETE FROM uptime.check_runs WHERE monitor_id=$1`, monID)
		_, _ = conn.Exec(c, `DELETE FROM uptime.schedule_segments WHERE monitor_id=$1`, monID)
		_, _ = conn.Exec(c, `DELETE FROM uptime.monitors WHERE id=$1`, monID)
	}()

	body := []byte(`{"reason":"abuse report"}`)
	ver, _ := userVersion(t, conn, subject.UserID)

	res, err := admin.SuspendAccount(context.Background(), conn, actor,
		subject.UserID, admin.SuspendInput{
			ExpectedVersion: ver, Reason: "abuse report",
		}, "k-sus-1", body, time.Now())
	if err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if res.Status != 200 || res.Response["status"] != "DISABLED" {
		t.Fatalf("unexpected suspend result: %+v", res)
	}

	ctx := context.Background()
	var status string
	var sec int64
	var disabledAt *time.Time
	if err := conn.QueryRow(ctx, `
		SELECT status, security_version, disabled_at FROM uptime.users
		WHERE id=$1`, subject.UserID).Scan(&status, &sec, &disabledAt); err != nil {
		t.Fatal(err)
	}
	if status != "DISABLED" || disabledAt == nil || sec != 2 {
		t.Fatalf("user row: status=%s sec=%d disabled_at=%v", status, sec, disabledAt)
	}
	var liveSessions int
	_ = conn.QueryRow(ctx, `
		SELECT count(*) FROM uptime.sessions
		WHERE user_id=$1 AND revoked_at IS NULL`, subject.UserID).
		Scan(&liveSessions)
	if liveSessions != 0 {
		t.Fatalf("sessions not revoked: %d", liveSessions)
	}
	var openSeg int
	_ = conn.QueryRow(ctx, `
		SELECT count(*) FROM uptime.schedule_segments
		WHERE id=$1 AND ends_at IS NULL`, segID).Scan(&openSeg)
	if openSeg != 0 {
		t.Fatal("open segment survived suspend")
	}
	var newGen int64
	_ = conn.QueryRow(ctx, `SELECT generation FROM uptime.monitors WHERE id=$1`,
		monID).Scan(&newGen)
	if newGen != gen+1 {
		t.Fatalf("generation not fenced: %d -> %d", gen, newGen)
	}
	var audit int
	_ = conn.QueryRow(ctx, `
		SELECT count(*) FROM uptime.audit_events
		WHERE action='account.suspend' AND subject_id=$1`,
		subject.UserID.String()).Scan(&audit)
	if audit != 1 {
		t.Fatalf("audit rows=%d", audit)
	}

	t.Run("duplicate suspend is idempotent no-op", func(t *testing.T) {
		ver2, sec2 := userVersion(t, conn, subject.UserID)
		res, err := admin.SuspendAccount(ctx, conn, actor, subject.UserID,
			admin.SuspendInput{ExpectedVersion: ver2, Reason: "again"},
			"k-sus-2", body, time.Now())
		if err != nil {
			t.Fatalf("dup suspend: %v", err)
		}
		if res.Response["already"] != true {
			t.Fatalf("expected already:true, got %+v", res.Response)
		}
		_, sec3 := userVersion(t, conn, subject.UserID)
		if sec3 != sec2 {
			t.Fatalf("no-op bumped epoch: %d -> %d", sec2, sec3)
		}
	})

	t.Run("stale version is 409", func(t *testing.T) {
		victim, vCleanup := plainUser(t, conn, "c60-stale")
		defer vCleanup()
		v, _ := userVersion(t, conn, victim.UserID)
		_, err := admin.SuspendAccount(ctx, conn, actor, victim.UserID,
			admin.SuspendInput{ExpectedVersion: v + 5, Reason: "x"},
			"k-sus-3", body, time.Now())
		if !errors.Is(err, admin.ErrStaleEpoch) {
			t.Fatalf("want ErrStaleEpoch, got %v", err)
		}
	})

	t.Run("security admin cannot suspend super subject", func(t *testing.T) {
		// SECURITY_ADMIN holds users:manage but not roles:manage —
		// the protected-subject rule must still block the mutation.
		sa, saCleanup := authFixture(t, conn, "c60-sec")
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
		aver, _ := userVersion(t, conn, actor.UserID)
		_, err := admin.SuspendAccount(ctx, conn, sa, actor.UserID,
			admin.SuspendInput{ExpectedVersion: aver, Reason: "x"},
			"k-sus-4", body, time.Now())
		if !errors.Is(err, admin.ErrForbidden) {
			t.Fatalf("want ErrForbidden, got %v", err)
		}
	})

	t.Run("suspending last superadmin is 409", func(t *testing.T) {
		aver, _ := userVersion(t, conn, actor.UserID)
		_, err := admin.SuspendAccount(ctx, conn, actor, actor.UserID,
			admin.SuspendInput{ExpectedVersion: aver, Reason: "x"},
			"k-sus-5", body, time.Now())
		if !errors.Is(err, admin.ErrLastSuperAdmin) {
			t.Fatalf("want ErrLastSuperAdmin, got %v", err)
		}
		var st string
		_ = conn.QueryRow(ctx, `SELECT status FROM uptime.users WHERE id=$1`,
			actor.UserID).Scan(&st)
		if st != "ACTIVE" {
			t.Fatalf("denied suspend still changed status: %s", st)
		}
	})
}

func TestAccountRestore(t *testing.T) {
	conn := connect(t)
	actor, cleanup := superActor(t, conn, "c60-res")
	defer cleanup()
	subject, subCleanup := plainUser(t, conn, "c60-rst")
	defer subCleanup()
	monID, _, _ := seedMonitorWithSegment(t, conn, subject.UserID)
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.Exec(c, `DELETE FROM uptime.check_runs WHERE monitor_id=$1`, monID)
		_, _ = conn.Exec(c, `DELETE FROM uptime.schedule_segments WHERE monitor_id=$1`, monID)
		_, _ = conn.Exec(c, `DELETE FROM uptime.monitors WHERE id=$1`, monID)
	}()
	ctx := context.Background()
	body := []byte(`{"reason":"cleared"}`)

	ver, _ := userVersion(t, conn, subject.UserID)
	if _, err := admin.SuspendAccount(ctx, conn, actor, subject.UserID,
		admin.SuspendInput{ExpectedVersion: ver, Reason: "suspend"},
		"k-rst-sus", body, time.Now()); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	// A second, user-paused monitor: restore must not touch it.
	var pausedID uuid.UUID
	if err := conn.QueryRow(ctx, `
		INSERT INTO uptime.monitors(id,user_id,name,target_url,method,
		  interval_seconds,timeout_seconds,is_paused,next_check_at)
		VALUES (gen_random_uuid(),$1,'p','https://p.test','GET',60,5,true,
		  now()-interval '1 day') RETURNING id`,
		subject.UserID).Scan(&pausedID); err != nil {
		t.Fatal(err)
	}
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.Exec(c, `DELETE FROM uptime.monitors WHERE id=$1`, pausedID)
	}()

	ver, secBefore := userVersion(t, conn, subject.UserID)
	res, err := admin.RestoreAccount(ctx, conn, actor, subject.UserID,
		admin.SuspendInput{ExpectedVersion: ver, Reason: "cleared"},
		"k-rst-1", body, time.Now())
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if res.Response["status"] != "ACTIVE" || res.Response["already"] != false {
		t.Fatalf("unexpected restore: %+v", res.Response)
	}

	var status string
	var sec int64
	var disabledAt *time.Time
	if err := conn.QueryRow(ctx, `
		SELECT status, security_version, disabled_at FROM uptime.users
		WHERE id=$1`, subject.UserID).Scan(&status, &sec, &disabledAt); err != nil {
		t.Fatal(err)
	}
	if status != "ACTIVE" || disabledAt != nil || sec != secBefore+1 {
		t.Fatalf("restored row: %s sec=%d disabled_at=%v", status, sec, disabledAt)
	}
	// Revoked sessions stay revoked — no resurrection.
	var live int
	_ = conn.QueryRow(ctx, `
		SELECT count(*) FROM uptime.sessions
		WHERE user_id=$1 AND revoked_at IS NULL`, subject.UserID).Scan(&live)
	if live != 0 {
		t.Fatalf("restore resurrected %d sessions", live)
	}
	// Eligible monitor is due at the first future slot; paused is not.
	var dueAt time.Time
	_ = conn.QueryRow(ctx, `SELECT next_check_at FROM uptime.monitors WHERE id=$1`,
		monID).Scan(&dueAt)
	if dueAt.After(time.Now().Add(time.Second)) {
		t.Fatalf("restored monitor not due: %v", dueAt)
	}
	var pausedDue time.Time
	_ = conn.QueryRow(ctx, `SELECT next_check_at FROM uptime.monitors WHERE id=$1`,
		pausedID).Scan(&pausedDue)
	if pausedDue.After(time.Now().Add(-time.Hour)) {
		t.Fatalf("paused monitor was re-anchored: %v", pausedDue)
	}
	// No segment is opened eagerly — admission opens it lazily.
	var open int
	_ = conn.QueryRow(ctx, `
		SELECT count(*) FROM uptime.schedule_segments
		WHERE monitor_id=$1 AND ends_at IS NULL`, monID).Scan(&open)
	if open != 0 {
		t.Fatalf("restore eagerly opened %d segments", open)
	}

	t.Run("restore of active account is no-op", func(t *testing.T) {
		ver, sec := userVersion(t, conn, subject.UserID)
		res, err := admin.RestoreAccount(ctx, conn, actor, subject.UserID,
			admin.SuspendInput{ExpectedVersion: ver, Reason: "again"},
			"k-rst-2", body, time.Now())
		if err != nil {
			t.Fatalf("dup restore: %v", err)
		}
		if res.Response["already"] != true {
			t.Fatalf("expected already:true, got %+v", res.Response)
		}
		_, sec2 := userVersion(t, conn, subject.UserID)
		if sec2 != sec {
			t.Fatalf("no-op bumped epoch")
		}
	})
}
