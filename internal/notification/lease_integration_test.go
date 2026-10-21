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

	// SUPPRESSED predecessor is the authorized skip — recovery flows.
	if _, err := c.Exec(context.Background(), `
		UPDATE uptime.notification_outbox SET state='SUPPRESSED'
		WHERE id=$1`, down); err != nil {
		t.Fatal(err)
	}
	claims, err = ClaimDue(context.Background(), c, testLease)
	if err != nil || len(claims) != 1 || claims[0].ID != rec {
		t.Fatalf("recovery after suppress: %+v %v", claims, err)
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
