//go:build integration

package engine

import (
	"context"
	"testing"
	"time"
)

// TestSuspendedOwnerFence proves the async half of account
// suspension (spec-07 F-19): a user suspended between reservation
// and finalize can neither admit new work nor commit the in-flight
// observation — the owner-row fence is the linearization point.
func TestSuspendedOwnerFence(t *testing.T) {
	ctx := context.Background()
	conn := engineConn(t)
	ownerID, monID := seedDue(t)
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.Exec(c, `DELETE FROM uptime.check_runs WHERE monitor_id=$1`, monID)
		_, _ = conn.Exec(c, `DELETE FROM uptime.schedule_segments WHERE monitor_id=$1`, monID)
		_, _ = conn.Exec(c, `DELETE FROM uptime.monitors WHERE id=$1`, monID)
		_, _ = conn.Exec(c, `DELETE FROM uptime.sessions WHERE user_id=$1`, ownerID)
		_, _ = conn.Exec(c, `DELETE FROM uptime.user_roles WHERE user_id=$1`, ownerID)
		_, _ = conn.Exec(c, `DELETE FROM uptime.users WHERE id=$1`, ownerID)
	}()

	// Reserve an in-flight run before the suspension.
	res, err := ReserveRun(ctx, conn, monID, 1, caps, 11)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}

	// Suspend the owner — the same writes SuspendAccount commits.
	if _, err := conn.Exec(ctx, `
		UPDATE uptime.users SET status='DISABLED',
		  disabled_at=clock_timestamp(), security_version=security_version+1,
		  version=version+1 WHERE id=$1`, ownerID); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `
		UPDATE uptime.monitors SET generation=generation+1
		WHERE id=$1`, monID); err != nil {
		t.Fatal(err)
	}

	// Admission fence: the suspended owner's monitor is never due.
	var admitted int
	if err := conn.QueryRow(ctx, `
		SELECT count(*) FROM uptime.monitors m
		JOIN uptime.users u ON u.id = m.user_id AND u.status='ACTIVE'
		WHERE m.id=$1 AND m.next_check_at <= clock_timestamp()
		  AND NOT m.is_paused AND m.deleted_at IS NULL`, monID).
		Scan(&admitted); err != nil {
		t.Fatal(err)
	}
	if admitted != 0 {
		t.Fatal("suspended owner's monitor still admittable")
	}
	// ReserveRun also joins owner status — a direct call must fail.
	if _, err := ReserveRun(ctx, conn, monID, 2, caps, 11); err == nil {
		t.Fatal("ReserveRun admitted a suspended owner's monitor")
	}

	// Finalize fence: the pre-suspension reservation goes stale at the
	// owner row — no committed result, no health flip.
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	verdict, err := ValidateResultIdentity(ctx, tx, res.Epoch,
		FinalizeIdentity{
			OwnerID: ownerID, MonitorID: monID, RunID: res.RunID,
			Generation: res.Generation, SegmentID: res.SegmentID,
			Sequence: res.Sequence, Epoch: res.Epoch,
		})
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if verdict != IdentityStale {
		t.Fatalf("verdict=%v, want IdentityStale", verdict)
	}
}
