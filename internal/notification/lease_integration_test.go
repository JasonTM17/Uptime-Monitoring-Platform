//go:build integration

package notification

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var testLease = LeaseConfig{Batch: 10, LeaseFor: time.Minute, MaxAttempts: 3}

func cleanOutbox(t *testing.T, c *pgx.Conn) {
	t.Helper()
	if _, err := c.Exec(context.Background(),
		`DELETE FROM uptime.notification_outbox`); err != nil {
		t.Fatal(err)
	}
}

// seedOutbox inserts one row with full state control — the lease
// tests need states the writer path never produces directly.
func seedOutbox(t *testing.T, c *pgx.Conn, f fixture, ch uuid.UUID,
	kind string, pred *uuid.UUID, state string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	key := kind + ":" + uuid.NewString()[:8]
	var leaseTok interface{}
	var leaseExp interface{}
	attempts := 0
	if state == "LEASED" {
		tok := uuid.New()
		leaseTok = tok
		exp := time.Now().Add(time.Minute)
		leaseExp = exp
		attempts = 1
	}
	err := c.QueryRow(context.Background(), `
		INSERT INTO uptime.notification_outbox
		  (id,user_id,monitor_id,incident_id,channel_id,event_kind,
		   event_key,predecessor_id,channel_version,safe_payload,state,
		   attempts,lease_token,lease_expires_at)
		VALUES (gen_random_uuid(),$1,$2,$3,$4,$5,$6,$7,1,'{}',$8,$9,$10,$11)
		RETURNING id`,
		f.userID, f.monID, f.incID, ch, kind, key, pred, state,
		attempts, leaseTok, leaseExp).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func stateOf(t *testing.T, c *pgx.Conn, id uuid.UUID) string {
	t.Helper()
	var s string
	if err := c.QueryRow(context.Background(),
		`SELECT state FROM uptime.notification_outbox WHERE id=$1`,
		id).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

// Two concurrent claimers can never hold the same active lease —
// SKIP LOCKED partitions the due set.
func TestOutboxClaimExclusive(t *testing.T) {

	c1, c2 := conn(t), conn(t)
	cleanOutbox(t, c1)
	f := seedBase(t, c1)
	ch := mkChannel(t, c1, f, "VERIFIED", true, false)
	id := seedOutbox(t, c1, f, ch, "DOWN", nil, "PENDING")

	claims1, err := ClaimDue(context.Background(), c1, testLease)
	if err != nil {
		t.Fatal(err)
	}
	if len(claims1) != 1 || claims1[0].ID != id {
		t.Fatalf("claims %+v", claims1)
	}
	if stateOf(t, c1, id) != "LEASED" {
		t.Fatal("not leased")
	}
	// Claimer two sees nothing — the row is LEASED, and even if it
	// were PENDING the row lock inside c1's claim already released;
	// the state fence is what matters.
	if _, err := ClaimDue(context.Background(), c2, testLease); err == nil {
		t.Fatal("second claimer got work")
	}
	// Attempts counted once; the lease token is set.
	var attempts int
	var tok *uuid.UUID
	c1.QueryRow(context.Background(),
		`SELECT attempts, lease_token FROM uptime.notification_outbox WHERE id=$1`,
		id).Scan(&attempts, &tok)
	if attempts != 1 || tok == nil {
		t.Fatalf("attempts=%d token=%v", attempts, tok)
	}
}

// Expired lease re-enters the stream; a still-live lease does not.
func TestExpiredLeaseRecovery(t *testing.T) {

	c := conn(t)
	cleanOutbox(t, c)
	f := seedBase(t, c)
	ch := mkChannel(t, c, f, "VERIFIED", true, false)

	ch2 := mkChannel(t, c, f, "VERIFIED", true, false)
	live := seedOutbox(t, c, f, ch, "DOWN", nil, "PENDING")
	dead := seedOutbox(t, c, f, ch2, "DOWN", nil, "PENDING")

	// Lease both, then force one's expiry into the past.
	claims, err := ClaimDue(context.Background(), c, testLease)
	if err != nil || len(claims) != 2 {
		t.Fatalf("claims %v %v", claims, err)
	}
	if _, err := c.Exec(context.Background(), `
		UPDATE uptime.notification_outbox
		SET lease_expires_at=clock_timestamp()-interval '1 second'
		WHERE id=$1`, dead); err != nil {
		t.Fatal(err)
	}
	n, err := ReclaimExpired(context.Background(), c, testLease)
	if err != nil || n != 1 {
		t.Fatalf("reclaimed %d err=%v", n, err)
	}
	if stateOf(t, c, dead) != "PENDING" {
		t.Fatal("expired lease not reclaimed")
	}
	if stateOf(t, c, live) != "LEASED" {
		t.Fatal("live lease reclaimed")
	}
}

// A stale token ACKs nothing — only the current lease owner can
// terminalize the row.
func TestStaleLeaseAck(t *testing.T) {

	c := conn(t)
	cleanOutbox(t, c)
	f := seedBase(t, c)
	ch := mkChannel(t, c, f, "VERIFIED", true, false)
	id := seedOutbox(t, c, f, ch, "DOWN", nil, "PENDING")

	claims, err := ClaimDue(context.Background(), c, testLease)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim %v %v", claims, err)
	}
	stale := claims[0].LeaseToken

	// Force expiry + reclaim + re-lease: the row gets a NEW token.
	if _, err := c.Exec(context.Background(), `
		UPDATE uptime.notification_outbox
		SET lease_expires_at=clock_timestamp()-interval '1 second'
		WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := ReclaimExpired(context.Background(), c, testLease); err != nil {
		t.Fatal(err)
	}
	claims2, err := ClaimDue(context.Background(), c, testLease)
	if err != nil || len(claims2) != 1 {
		t.Fatalf("reclaim claim %v %v", claims2, err)
	}
	if claims2[0].LeaseToken == stale {
		t.Fatal("reclaim reused token")
	}

	// Old token must not mark SENT.
	ok, err := AckDelivery(context.Background(), c, id, stale)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("stale token ACKed")
	}
	if stateOf(t, c, id) != "LEASED" {
		t.Fatal("stale ACK mutated state")
	}
	// Current token ACKs.
	ok, err = AckDelivery(context.Background(), c, id, claims2[0].LeaseToken)
	if err != nil || !ok {
		t.Fatalf("live ack %v %v", ok, err)
	}
	if stateOf(t, c, id) != "SENT" {
		t.Fatal("not sent")
	}
}

// A RECOVERY whose DOWN predecessor is PENDING or DEAD is not
// claimable — causal order cannot be overtaken.
func TestPredecessorBlocksClaim(t *testing.T) {

	c := conn(t)
	cleanOutbox(t, c)
	f := seedBase(t, c)
	ch := mkChannel(t, c, f, "VERIFIED", true, false)

	down := seedOutbox(t, c, f, ch, "DOWN", nil, "PENDING")
	rec := seedOutbox(t, c, f, ch, "RECOVERY", &down, "PENDING")

	// DOWN head is due → claims first; RECOVERY stays blocked.
	claims, err := ClaimDue(context.Background(), c, testLease)
	if err != nil || len(claims) != 1 || claims[0].ID != down {
		t.Fatalf("claims %+v %v", claims, err)
	}
	if stateOf(t, c, rec) != "PENDING" {
		t.Fatal("recovery claimed early")
	}

	// DEAD predecessor also blocks — operations must resolve the head.
	if _, err := c.Exec(context.Background(), `
		UPDATE uptime.notification_outbox
		SET state='DEAD', lease_token=NULL, lease_expires_at=NULL
		WHERE id=$1`, down); err != nil {
		t.Fatal(err)
	}
	if _, err := ClaimDue(context.Background(), c, testLease); err == nil {
		t.Fatal("recovery claimed behind DEAD predecessor")
	}

	// SUPPRESSED predecessor must never release a child to send —
	// a channel that never learned "down" must never hear
	// "recovered". The same claim pass cascades the authorized skip:
	// the child terminalizes SUPPRESSED itself.
	if _, err := c.Exec(context.Background(), `
		UPDATE uptime.notification_outbox SET state='SUPPRESSED'
		WHERE id=$1`, down); err != nil {
		t.Fatal(err)
	}
	claims, err = ClaimDue(context.Background(), c, testLease)
	if len(claims) != 0 && err == nil {
		t.Fatalf("claimed behind suppressed head: %+v", claims)
	}
	if stateOf(t, c, rec) != "SUPPRESSED" {
		t.Fatalf("cascade suppress failed: %s", stateOf(t, c, rec))
	}
}

// Reschedule: under budget PENDING, at budget DEAD; stale token noop.
func TestRescheduleBudget(t *testing.T) {

	c := conn(t)
	cleanOutbox(t, c)
	f := seedBase(t, c)
	ch := mkChannel(t, c, f, "VERIFIED", true, false)
	id := seedOutbox(t, c, f, ch, "DOWN", nil, "PENDING")

	cfg := LeaseConfig{Batch: 5, LeaseFor: time.Minute, MaxAttempts: 2}
	for i := 1; i <= 2; i++ {
		claims, err := ClaimDue(context.Background(), c, cfg)
		if err != nil || len(claims) != 1 {
			t.Fatalf("claim %d: %v %v", i, claims, err)
		}
		d, err := RescheduleDelivery(context.Background(), c, id,
			claims[0].LeaseToken, time.Now().Add(-time.Second),
			"RETRYABLE", cfg.MaxAttempts)
		if err != nil {
			t.Fatal(err)
		}
		want := DispositionPending
		if i == cfg.MaxAttempts {
			want = DispositionDead
		}
		if d != want {
			t.Fatalf("attempt %d: %s want %s", i, d, want)
		}
	}
	if stateOf(t, c, id) != "DEAD" {
		t.Fatal("budget not terminal")
	}
	var code string
	c.QueryRow(context.Background(),
		`SELECT last_error_code FROM uptime.notification_outbox WHERE id=$1`,
		id).Scan(&code)
	if code != "RETRYABLE" {
		t.Fatalf("error code %q", code)
	}
}

func TestRateLimitAccountingAndLeaseFencing(t *testing.T) {
	ctx := context.Background()
	c := conn(t)
	cleanOutbox(t, c)
	f := seedBase(t, c)
	ch := mkChannel(t, c, f, "VERIFIED", true, false)
	id := seedOutbox(t, c, f, ch, "DOWN", nil, "PENDING")
	cfg := LeaseConfig{Batch: 5, LeaseFor: time.Minute, MaxAttempts: 8}
	for n := 1; n <= 7; n++ {
		claims, err := ClaimDue(ctx, c, cfg)
		if err != nil || len(claims) != 1 {
			t.Fatalf("claim %d: %v", n, err)
		}
		stale, err := RescheduleDelivery(ctx, c, id, uuid.New(), time.Now(), "RATE_LIMITED", 64)
		if err != nil || stale != DispositionStale {
			t.Fatalf("stale: %s %v", stale, err)
		}
		d, err := RescheduleDelivery(ctx, c, id, claims[0].LeaseToken, time.Now().Add(-time.Second), "RATE_LIMITED", 64)
		if err != nil || d != DispositionPending {
			t.Fatalf("refusal %d: %s %v", n, d, err)
		}
	}
	claims, err := ClaimDue(ctx, c, cfg)
	if err != nil || len(claims) != 1 {
		t.Fatalf("send claim: %v", err)
	}
	if claims[0].Attempts != 8 || claims[0].RateLimitRefusals != 7 {
		t.Fatalf("counters: %+v", claims[0])
	}
	d, err := RescheduleDelivery(ctx, c, id, claims[0].LeaseToken, time.Now().Add(-time.Second), "RETRYABLE", 8)
	if err != nil || d != DispositionPending {
		t.Fatalf("first failure: %s %v", d, err)
	}
	claims, err = ClaimDue(ctx, c, cfg)
	if err != nil || len(claims) != 1 {
		t.Fatalf("crash claim: %v", err)
	}
	if _, err = c.Exec(ctx, `UPDATE uptime.notification_outbox SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if n, err := ReclaimExpired(ctx, c, cfg); err != nil || n != 1 {
		t.Fatalf("reclaim: %d %v", n, err)
	}
	if stateOf(t, c, id) != "PENDING" {
		t.Fatal("reclaim ignored refusal counter")
	}
}

func TestRateLimitRefusalCeiling(t *testing.T) {
	ctx := context.Background()
	c := conn(t)
	cleanOutbox(t, c)
	f := seedBase(t, c)
	ch := mkChannel(t, c, f, "VERIFIED", true, false)
	id := seedOutbox(t, c, f, ch, "DOWN", nil, "PENDING")
	for n := 1; n <= 3; n++ {
		claims, err := ClaimDue(ctx, c, testLease)
		if err != nil || len(claims) != 1 {
			t.Fatalf("claim %d: %v", n, err)
		}
		d, err := RescheduleDelivery(ctx, c, id, claims[0].LeaseToken, time.Now().Add(-time.Second), "RATE_LIMITED", 3)
		want := DispositionPending
		if n == 3 {
			want = DispositionDead
		}
		if err != nil || d != want {
			t.Fatalf("refusal %d: %s %v", n, d, err)
		}
	}
}

func TestEffectiveBudgetExhaustionAfterRefusals(t *testing.T) {
	ctx := context.Background()
	c := conn(t)
	cleanOutbox(t, c)
	f := seedBase(t, c)
	cfg := LeaseConfig{Batch: 5, LeaseFor: time.Minute, MaxAttempts: 8}
	for _, mode := range []string{"retry", "crash"} {
		t.Run(mode, func(t *testing.T) {
			ch := mkChannel(t, c, f, "VERIFIED", true, false)
			id := seedOutbox(t, c, f, ch, "DOWN", nil, "PENDING")
			if _, err := c.Exec(ctx, `UPDATE uptime.notification_outbox SET attempts=14, rate_limit_refusals=7 WHERE id=$1`, id); err != nil {
				t.Fatal(err)
			}
			claims, err := ClaimDue(ctx, c, cfg)
			if err != nil || len(claims) != 1 {
				t.Fatalf("claim: %v", err)
			}
			if mode == "retry" {
				d, err := RescheduleDelivery(ctx, c, id, claims[0].LeaseToken, time.Now(), "RETRYABLE", 8)
				if err != nil || d != DispositionDead {
					t.Fatalf("retry: %s %v", d, err)
				}
			} else {
				if _, err := c.Exec(ctx, `UPDATE uptime.notification_outbox SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, id); err != nil {
					t.Fatal(err)
				}
				if n, err := ReclaimExpired(ctx, c, cfg); err != nil || n != 1 {
					t.Fatalf("reclaim: %d %v", n, err)
				}
				if stateOf(t, c, id) != "DEAD" {
					t.Fatal("ambiguous eighth claim must exhaust budget")
				}
			}
		})
	}
}

func TestExternalProviderRateLimitDeductionAndRetryEligibility(t *testing.T) {
	ctx := context.Background()
	c := conn(t)
	cleanOutbox(t, c)
	f := seedBase(t, c)
	ch := mkChannel(t, c, f, "VERIFIED", true, false)
	id := seedOutbox(t, c, f, ch, "DOWN", nil, "PENDING")
	cfg := LeaseConfig{Batch: 5, LeaseFor: time.Minute, MaxAttempts: 8}

	// 7 consecutive external rate limit refusals.
	for n := 1; n <= 7; n++ {
		claims, err := ClaimDue(ctx, c, cfg)
		if err != nil || len(claims) != 1 {
			t.Fatalf("claim %d: %v", n, err)
		}
		// Provider returns 429 -> Reschedule with RATE_LIMITED.
		d, err := RescheduleDelivery(ctx, c, id, claims[0].LeaseToken, time.Now().Add(-time.Second), "RATE_LIMITED", 64)
		if err != nil || d != DispositionPending {
			t.Fatalf("refusal %d: %s %v", n, d, err)
		}
	}

	// Verify database counters after 7 rate limit refusals:
	var attempts, refusals int
	var st string
	if err := c.QueryRow(ctx, `SELECT state, attempts, rate_limit_refusals FROM uptime.notification_outbox WHERE id=$1`, id).Scan(&st, &attempts, &refusals); err != nil {
		t.Fatal(err)
	}
	if st != "PENDING" || attempts != 7 || refusals != 7 {
		t.Fatalf("after 7 refusals: state=%s attempts=%d refusals=%d", st, attempts, refusals)
	}

	// 8th claim: provider fails with first transient error.
	claims, err := ClaimDue(ctx, c, cfg)
	if err != nil || len(claims) != 1 {
		t.Fatalf("first transient claim: %v", err)
	}
	if claims[0].Attempts != 8 || claims[0].RateLimitRefusals != 7 {
		t.Fatalf("first transient claim counters: %+v", claims[0])
	}
	// Reschedule with RETRYABLE (effective attempts spent = 8 - 7 = 1 < 8).
	d, err := RescheduleDelivery(ctx, c, id, claims[0].LeaseToken, time.Now().Add(-time.Second), "RETRYABLE", 8)
	if err != nil || d != DispositionPending {
		t.Fatalf("first transient failure must be PENDING: %s %v", d, err)
	}

	// Check DB state: still PENDING, transient attempts = 1.
	if err := c.QueryRow(ctx, `SELECT state, attempts, rate_limit_refusals FROM uptime.notification_outbox WHERE id=$1`, id).Scan(&st, &attempts, &refusals); err != nil {
		t.Fatal(err)
	}
	if st != "PENDING" || attempts != 8 || refusals != 7 {
		t.Fatalf("after first transient failure: state=%s attempts=%d refusals=%d", st, attempts, refusals)
	}

	// Run transient failures 2 through 7 (total claims 9 through 14).
	for n := 2; n <= 7; n++ {
		claims, err := ClaimDue(ctx, c, cfg)
		if err != nil || len(claims) != 1 {
			t.Fatalf("transient claim %d: %v", n, err)
		}
		d, err := RescheduleDelivery(ctx, c, id, claims[0].LeaseToken, time.Now().Add(-time.Second), "RETRYABLE", 8)
		if err != nil || d != DispositionPending {
			t.Fatalf("transient failure %d must be PENDING: %s %v", n, d, err)
		}
	}

	// 8th transient failure (claim 15, attempts=15, refusals=7 -> 15-7=8 >= 8 -> DEAD).
	claims, err = ClaimDue(ctx, c, cfg)
	if err != nil || len(claims) != 1 {
		t.Fatalf("8th transient claim: %v", err)
	}
	d, err = RescheduleDelivery(ctx, c, id, claims[0].LeaseToken, time.Now().Add(-time.Second), "RETRYABLE", 8)
	if err != nil || d != DispositionDead {
		t.Fatalf("8th transient failure must be DEAD: %s %v", d, err)
	}
	if stateOf(t, c, id) != "DEAD" {
		t.Fatalf("expected state DEAD after 8 transient failures")
	}
}
