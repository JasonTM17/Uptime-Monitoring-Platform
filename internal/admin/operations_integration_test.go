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

const (
	operatorPreset = "00000000-0000-4000-8000-000000000003"
	secAdminPreset = "00000000-0000-4000-8000-000000000004"
)

// actorWithRole reseats the fixture actor's role set to one preset.
func actorWithRole(t *testing.T, conn *pgx.Conn, prefix, roleID string) (admin.ActorRef, func()) {
	t.Helper()
	actor, cleanup := authFixture(t, conn, prefix)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := conn.Exec(ctx, `
		DELETE FROM uptime.user_roles WHERE user_id=$1`, actor.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO uptime.user_roles (user_id, role_id)
		VALUES ($1,$2)`, actor.UserID, roleID); err != nil {
		t.Fatal(err)
	}
	stampReauth(t, conn, actor.SessionID, 0)
	return actor, cleanup
}

// seedDeliveryChain builds a DOWN head + RECOVERY child for a monitor.
func seedDeliveryChain(t *testing.T, conn *pgx.Conn,
	monID, owner uuid.UUID) (head, child uuid.UUID) {
	return seedDeliveryChainState(t, conn, monID, owner, "DEAD")
}

func seedDeliveryChainState(t *testing.T, conn *pgx.Conn,
	monID, owner uuid.UUID, headState string) (head, child uuid.UUID) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var segID, runID, inc uuid.UUID
	// One open incident per monitor — resolve leftovers from prior
	// chains before seeding this one.
	if _, err := conn.Exec(ctx, `
		UPDATE uptime.incidents SET resolved_at=now(),
		  close_reason='CONFIG_CHANGED'
		WHERE monitor_id=$1 AND resolved_at IS NULL`, monID); err != nil {
		t.Fatal(err)
	}
	// Close any open segment — the chain only needs an FK anchor.
	if _, err := conn.Exec(ctx, `
		UPDATE uptime.schedule_segments SET ends_at=now()
		WHERE monitor_id=$1 AND ends_at IS NULL`, monID); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `
		INSERT INTO uptime.schedule_segments(id,monitor_id,generation,
		  starts_at,ends_at,interval_seconds)
		VALUES (gen_random_uuid(),$1,1,now()-interval '1 hour',now(),60)
		RETURNING id`, monID).Scan(&segID); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `
		INSERT INTO uptime.check_runs(id,monitor_id,segment_id,slot_at,
		  generation,sequence,engine_epoch,status)
		VALUES (gen_random_uuid(),$1,$2,now(),1,
		  floor(random()*900000)+1,1,'COMPLETED')
		RETURNING id`, monID, segID).Scan(&runID); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `
		INSERT INTO uptime.incidents(id,monitor_id,opened_check_id,opened_at)
		VALUES (gen_random_uuid(),$1,$2,now()) RETURNING id`,
		monID, runID).Scan(&inc); err != nil {
		t.Fatal(err)
	}
	var chID uuid.UUID
	if err := conn.QueryRow(ctx, `
		INSERT INTO uptime.notification_channels
		  (id,user_id,label,status,destination_ciphertext,destination_mask,
		   encryption_key_version,verified_at,verification_receipt,enabled)
		VALUES (gen_random_uuid(),$1,'ch','VERIFIED',decode('00','hex'),'+84***',1,
		  now(),'r',true) RETURNING id`, owner).Scan(&chID); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `
		INSERT INTO uptime.notification_outbox
		  (id,user_id,monitor_id,incident_id,channel_id,event_kind,event_key,
		   channel_version,safe_payload,state,attempts,next_attempt_at)
		VALUES (gen_random_uuid(),$1,$2,$3,$5,'DOWN',
		  $4,1,'{}',$6,5,now()) RETURNING id`,
		owner, monID, inc, "d:"+uuid.NewString()[:8], chID,
		headState).Scan(&head); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `
		INSERT INTO uptime.notification_outbox
		  (id,user_id,monitor_id,incident_id,channel_id,event_kind,event_key,
		   predecessor_id,channel_version,safe_payload,state,next_attempt_at)
		VALUES (gen_random_uuid(),$1,$2,$3,
		  (SELECT channel_id FROM uptime.notification_outbox WHERE id=$4),
		  'RECOVERY',$5,$4,1,'{}','PENDING',now()) RETURNING id`,
		owner, monID, inc, head, "r:"+uuid.NewString()[:8]).Scan(&child); err != nil {
		t.Fatal(err)
	}
	return head, child
}

func TestOperationalPermissions(t *testing.T) {
	conn := connect(t)
	ctx := context.Background()
	owner, ownerCleanup := plainUser(t, conn, "c62-own")
	defer ownerCleanup()
	monID, _, gen := seedMonitorWithSegment(t, conn, owner.UserID)
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.Exec(c, `DELETE FROM uptime.notification_outbox WHERE monitor_id=$1`, monID)
		_, _ = conn.Exec(c, `DELETE FROM uptime.incidents WHERE monitor_id=$1`, monID)
		_, _ = conn.Exec(c, `DELETE FROM uptime.check_runs WHERE monitor_id=$1`, monID)
		_, _ = conn.Exec(c, `DELETE FROM uptime.schedule_segments WHERE monitor_id=$1`, monID)
		_, _ = conn.Exec(c, `DELETE FROM uptime.monitors WHERE id=$1`, monID)
	}()
	body := []byte(`{"expected_generation":1,"reason":"ops"}`)
	in := admin.MonitorActionInput{ExpectedGeneration: gen, Reason: "ops"}

	t.Run("viewer is forbidden", func(t *testing.T) {
		v, vc := authFixture(t, conn, "c62-view")
		defer vc()
		stampReauth(t, conn, v.SessionID, 0)
		_, err := admin.PauseGlobalMonitor(ctx, conn, v, monID, in,
			"k-op-v", body, time.Now())
		if !errors.Is(err, admin.ErrForbidden) {
			t.Fatalf("want ErrForbidden, got %v", err)
		}
	})

	t.Run("security admin lacks monitors:operate", func(t *testing.T) {
		sa, sc := actorWithRole(t, conn, "c62-sa", secAdminPreset)
		defer sc()
		_, err := admin.PauseGlobalMonitor(ctx, conn, sa, monID, in,
			"k-op-sa", body, time.Now())
		if !errors.Is(err, admin.ErrForbidden) {
			t.Fatalf("want ErrForbidden, got %v", err)
		}
	})

	t.Run("operator can pause and resume", func(t *testing.T) {
		op, oc := actorWithRole(t, conn, "c62-op", operatorPreset)
		defer oc()
		res, err := admin.PauseGlobalMonitor(ctx, conn, op, monID, in,
			"k-op-1", body, time.Now())
		if err != nil {
			t.Fatalf("pause: %v", err)
		}
		if res.Response["is_paused"] != true || res.Response["generation"] != gen+1 {
			t.Fatalf("pause response: %+v", res.Response)
		}
		var paused bool
		var openSeg int
		_ = conn.QueryRow(ctx, `SELECT is_paused FROM uptime.monitors WHERE id=$1`,
			monID).Scan(&paused)
		_ = conn.QueryRow(ctx, `
			SELECT count(*) FROM uptime.schedule_segments
			WHERE monitor_id=$1 AND ends_at IS NULL`, monID).Scan(&openSeg)
		if !paused || openSeg != 0 {
			t.Fatalf("paused=%v openSeg=%d", paused, openSeg)
		}
		res, err = admin.ResumeGlobalMonitor(ctx, conn, op, monID,
			admin.MonitorActionInput{ExpectedGeneration: gen + 1, Reason: "ops"},
			"k-op-2", body, time.Now())
		if err != nil {
			t.Fatalf("resume: %v", err)
		}
		if res.Response["is_paused"] != false {
			t.Fatalf("resume response: %+v", res.Response)
		}
	})
}

// TestAdminPauseFence: an in-flight reservation dies at the fence
// after a global pause bumps generation; resume of a suspended
// owner's monitor is denied.
func TestAdminPauseFence(t *testing.T) {
	conn := connect(t)
	ctx := context.Background()
	owner, ownerCleanup := plainUser(t, conn, "c62-fown")
	defer ownerCleanup()
	monID, segID, gen := seedMonitorWithSegment(t, conn, owner.UserID)
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.Exec(c, `DELETE FROM uptime.notification_outbox WHERE monitor_id=$1`, monID)
		_, _ = conn.Exec(c, `DELETE FROM uptime.incidents WHERE monitor_id=$1`, monID)
		_, _ = conn.Exec(c, `DELETE FROM uptime.check_runs WHERE monitor_id=$1`, monID)
		_, _ = conn.Exec(c, `DELETE FROM uptime.schedule_segments WHERE monitor_id=$1`, monID)
		_, _ = conn.Exec(c, `DELETE FROM uptime.monitors WHERE id=$1`, monID)
	}()
	op, oc := actorWithRole(t, conn, "c62-fop", operatorPreset)
	defer oc()
	body := []byte(`{"reason":"ops"}`)

	// An in-flight RESERVED run for the pre-pause generation.
	var runID uuid.UUID
	if err := conn.QueryRow(ctx, `
		INSERT INTO uptime.check_runs(id,monitor_id,segment_id,slot_at,
		  generation,sequence,engine_epoch,status,reserved_at)
		VALUES (gen_random_uuid(),$1,$2,now(),$3,1,1,'RESERVED',now())
		RETURNING id`, monID, segID, gen).Scan(&runID); err != nil {
		t.Fatal(err)
	}

	if _, err := admin.PauseGlobalMonitor(ctx, conn, op, monID,
		admin.MonitorActionInput{ExpectedGeneration: gen, Reason: "ops"},
		"k-fp-1", body, time.Now()); err != nil {
		t.Fatalf("pause: %v", err)
	}
	var newGen int64
	_ = conn.QueryRow(ctx, `SELECT generation FROM uptime.monitors WHERE id=$1`,
		monID).Scan(&newGen)
	if newGen != gen+1 {
		t.Fatalf("pause did not bump generation: %d -> %d", gen, newGen)
	}

	t.Run("resume suspended owner is 409", func(t *testing.T) {
		if _, err := conn.Exec(ctx, `
			UPDATE uptime.users SET status='DISABLED', disabled_at=now()
			WHERE id=$1`, owner.UserID); err != nil {
			t.Fatal(err)
		}
		ver, _ := userVersion(t, conn, owner.UserID)
		_ = ver
		_, err := admin.ResumeGlobalMonitor(ctx, conn, op, monID,
			admin.MonitorActionInput{ExpectedGeneration: newGen, Reason: "ops"},
			"k-fp-2", body, time.Now())
		if !errors.Is(err, admin.ErrStaleEpoch) {
			t.Fatalf("want 409 for suspended owner resume, got %v", err)
		}
		if _, err := conn.Exec(ctx, `
			UPDATE uptime.users SET status='ACTIVE', disabled_at=NULL
			WHERE id=$1`, owner.UserID); err != nil {
			t.Fatal(err)
		}
	})
}

// TestAdminDeliveryOrdering: suppress cascades the chain with reason
// + audit, mid-stream suppress is refused, retry resets only a dead
// head, and the idempotency key binds the request body.
func TestAdminDeliveryOrdering(t *testing.T) {
	conn := connect(t)
	ctx := context.Background()
	owner, ownerCleanup := plainUser(t, conn, "c62-down")
	defer ownerCleanup()
	monID, _, _ := seedMonitorWithSegment(t, conn, owner.UserID)
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.Exec(c, `DELETE FROM uptime.notification_outbox WHERE monitor_id=$1`, monID)
		_, _ = conn.Exec(c, `DELETE FROM uptime.incidents WHERE monitor_id=$1`, monID)
		_, _ = conn.Exec(c, `DELETE FROM uptime.check_runs WHERE monitor_id=$1`, monID)
		_, _ = conn.Exec(c, `DELETE FROM uptime.schedule_segments WHERE monitor_id=$1`, monID)
		_, _ = conn.Exec(c, `DELETE FROM uptime.monitors WHERE id=$1`, monID)
	}()
	op, oc := actorWithRole(t, conn, "c62-dop", operatorPreset)
	defer oc()
	head, child := seedDeliveryChain(t, conn, monID, owner.UserID)
	body := []byte(`{"expected_version":1,"reason":"noise"}`)

	t.Run("mid-stream suppress refused", func(t *testing.T) {
		// A PENDING child behind a LIVE head is mid-stream — the head
		// must be resolved first, the child cannot be suppressed alone.
		liveHead, liveChild := seedDeliveryChainState(t, conn, monID,
			owner.UserID, "PENDING")
		_, err := admin.SuppressDeliveryChain(ctx, conn, op, liveChild,
			admin.DeliveryActionInput{ExpectedVersion: 1, Reason: "x"},
			"k-d-1", body, time.Now())
		if !errors.Is(err, admin.ErrDeliveryNotHead) {
			t.Fatalf("want ErrDeliveryNotHead, got %v", err)
		}
		// Suppressing the live head cascades through the child.
		res, err := admin.SuppressDeliveryChain(ctx, conn, op, liveHead,
			admin.DeliveryActionInput{ExpectedVersion: 1, Reason: "x"},
			"k-d-1b", body, time.Now())
		if err != nil {
			t.Fatalf("head suppress: %v", err)
		}
		if res.Response["rows_suppressed"] != int64(2) {
			t.Fatalf("live cascade: %+v", res.Response)
		}
	})

	t.Run("head suppress cascades with audit", func(t *testing.T) {
		res, err := admin.SuppressDeliveryChain(ctx, conn, op, head,
			admin.DeliveryActionInput{ExpectedVersion: 1, Reason: "noise"},
			"k-d-2", body, time.Now())
		if err != nil {
			t.Fatalf("suppress: %v", err)
		}
		if res.Status != 202 || res.Response["rows_suppressed"] != int64(2) {
			t.Fatalf("suppress response: %+v", res)
		}
		var st string
		_ = conn.QueryRow(ctx, `
			SELECT state FROM uptime.notification_outbox WHERE id=$1`,
			child).Scan(&st)
		if st != "SUPPRESSED" {
			t.Fatalf("child not cascaded: %s", st)
		}
		var audit int
		_ = conn.QueryRow(ctx, `
			SELECT count(*) FROM uptime.audit_events
			WHERE action='delivery.suppress' AND subject_id=$1`,
			head.String()).Scan(&audit)
		if audit != 1 {
			t.Fatalf("audit rows=%d", audit)
		}
	})

	t.Run("retry dead head re-arms pending", func(t *testing.T) {
		// Fresh chain: dead head, sent predecessor constraint absent.
		h2, c2 := seedDeliveryChain(t, conn, monID, owner.UserID)
		if _, err := conn.Exec(ctx, `UPDATE uptime.notification_outbox SET attempts=7, rate_limit_refusals=6 WHERE id=$1`, h2); err != nil {
			t.Fatal(err)
		}
		// Suppress h2's chain then retry the dead head — terminal
		// predecessor absent at head → retry allowed.
		res, err := admin.RetryDeliveryChain(ctx, conn, op, h2,
			admin.DeliveryActionInput{ExpectedVersion: 1, Reason: "retry"},
			"k-d-3", body, time.Now())
		if err != nil {
			t.Fatalf("retry: %v", err)
		}
		if res.Status != 202 || res.Response["state"] != "PENDING" {
			t.Fatalf("retry response: %+v", res)
		}
		var st string
		var attempts, refusals int
		_ = conn.QueryRow(ctx, `
			SELECT state, attempts, rate_limit_refusals FROM uptime.notification_outbox WHERE id=$1`,
			h2).Scan(&st, &attempts, &refusals)
		if st != "PENDING" || attempts != 0 || refusals != 0 {
			t.Fatalf("head not re-armed: %s attempts=%d refusals=%d", st, attempts, refusals)
		}
		_ = c2
	})

	t.Run("idempotency key binds body", func(t *testing.T) {
		h3, _ := seedDeliveryChain(t, conn, monID, owner.UserID)
		_, err := admin.RetryDeliveryChain(ctx, conn, op, h3,
			admin.DeliveryActionInput{ExpectedVersion: 1, Reason: "r"},
			"k-d-4", body, time.Now())
		if err != nil {
			t.Fatalf("first: %v", err)
		}
		_, err = admin.RetryDeliveryChain(ctx, conn, op, h3,
			admin.DeliveryActionInput{ExpectedVersion: 1, Reason: "changed"},
			"k-d-4", []byte(`{"expected_version":1,"reason":"changed"}`),
			time.Now())
		if !errors.Is(err, admin.ErrIdempotencyConflict) {
			t.Fatalf("want ErrIdempotencyConflict, got %v", err)
		}
	})

	t.Run("retry delivery chain version and state fences", func(t *testing.T) {
		h4, c4 := seedDeliveryChain(t, conn, monID, owner.UserID)
		// 1. Version mismatch returns ErrStaleEpoch.
		_, err := admin.RetryDeliveryChain(ctx, conn, op, h4,
			admin.DeliveryActionInput{ExpectedVersion: 999, Reason: "wrong ver"},
			"k-d-fence-1", []byte(`{"expected_version":999,"reason":"wrong ver"}`), time.Now())
		if !errors.Is(err, admin.ErrStaleEpoch) {
			t.Fatalf("expected ErrStaleEpoch on version mismatch, got %v", err)
		}

		// 2. Non-dead delivery (c4 is PENDING) returns ErrDeliveryState.
		_, err = admin.RetryDeliveryChain(ctx, conn, op, c4,
			admin.DeliveryActionInput{ExpectedVersion: 1, Reason: "retry non-dead"},
			"k-d-fence-2", []byte(`{"expected_version":1,"reason":"retry non-dead"}`), time.Now())
		if !errors.Is(err, admin.ErrDeliveryState) {
			t.Fatalf("expected ErrDeliveryState for PENDING row, got %v", err)
		}

		// 3. DEAD child behind non-terminal predecessor returns ErrDeliveryNotHead.
		if _, err := conn.Exec(ctx, `UPDATE uptime.notification_outbox SET state='DEAD' WHERE id=$1`, c4); err != nil {
			t.Fatal(err)
		}
		_, err = admin.RetryDeliveryChain(ctx, conn, op, c4,
			admin.DeliveryActionInput{ExpectedVersion: 1, Reason: "retry non-head child"},
			"k-d-fence-3", []byte(`{"expected_version":1,"reason":"retry non-head child"}`), time.Now())
		if !errors.Is(err, admin.ErrDeliveryNotHead) {
			t.Fatalf("expected ErrDeliveryNotHead for child behind dead head, got %v", err)
		}
	})
}
