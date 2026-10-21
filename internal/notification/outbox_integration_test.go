//go:build integration

package notification

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func conn(t *testing.T) *pgx.Conn {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("TEST_DATABASE_URL required (disposable postgres-test)")
	}
	c, err := pgx.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(context.Background()) })
	return c
}

type fixture struct {
	userID, monID, segID, runID, incID uuid.UUID
}

// seedBase creates owner+monitor+segment+run+open incident.
func seedBase(t *testing.T, c *pgx.Conn) fixture {
	t.Helper()
	ctx := context.Background()
	f := fixture{}
	if err := c.QueryRow(ctx, `
		INSERT INTO uptime.users(id,email,password_hash,status,monitor_limit)
		VALUES (gen_random_uuid(),$1,'x','ACTIVE',10) RETURNING id`,
		"obx+"+uuid.NewString()[:8]+"@test.invalid").Scan(&f.userID); err != nil {
		t.Fatal(err)
	}
	if err := c.QueryRow(ctx, `
		INSERT INTO uptime.monitors(id,user_id,name,target_url,method,
		  interval_seconds,timeout_seconds,next_check_at)
		VALUES (gen_random_uuid(),$1,'m','https://x.test','GET',60,5,now())
		RETURNING id`, f.userID).Scan(&f.monID); err != nil {
		t.Fatal(err)
	}
	if err := c.QueryRow(ctx, `
		INSERT INTO uptime.schedule_segments(id,monitor_id,generation,starts_at,interval_seconds)
		VALUES (gen_random_uuid(),$1,1,now(),60) RETURNING id`, f.monID).Scan(&f.segID); err != nil {
		t.Fatal(err)
	}
	if err := c.QueryRow(ctx, `
		INSERT INTO uptime.check_runs(id,monitor_id,segment_id,slot_at,generation,
		  sequence,engine_epoch,status)
		VALUES (gen_random_uuid(),$1,$2,now(),1,1,1,'COMPLETED') RETURNING id`,
		f.monID, f.segID).Scan(&f.runID); err != nil {
		t.Fatal(err)
	}
	if err := c.QueryRow(ctx, `
		INSERT INTO uptime.incidents(id,monitor_id,opened_check_id,opened_at)
		VALUES (gen_random_uuid(),$1,$2,now()) RETURNING id`,
		f.monID, f.runID).Scan(&f.incID); err != nil {
		t.Fatal(err)
	}
	return f
}

// mkChannel creates a channel in the given state and binds it.
func mkChannel(t *testing.T, c *pgx.Conn, f fixture,
	status string, enabled bool, bind bool) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	var ct []byte
	var verAt interface{}
	var encV interface{}
	var receipt interface{}
	if status == "VERIFIED" {
		ct = []byte("ct")
		verAt = time.Now()
		one := 1
		encV = one
		receipt = "r"
	}
	var id uuid.UUID
	err := c.QueryRow(ctx, `
		INSERT INTO uptime.notification_channels
		  (id,user_id,label,status,destination_ciphertext,destination_mask,
		   encryption_key_version,verified_at,verification_receipt,enabled)
		VALUES (gen_random_uuid(),$1,'ch',$2,$3,'+84***',$4,$5,$6,$7)
		RETURNING id`,
		f.userID, status, ct, encV, verAt, receipt, enabled).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	if bind {
		if _, err := c.Exec(ctx, `
			INSERT INTO uptime.monitor_channels(monitor_id,channel_id,user_id)
			VALUES ($1,$2,$3)`, f.monID, id, f.userID); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

func tinput(f fixture, kind EventKind) TransitionInput {
	return TransitionInput{
		UserID: f.userID, MonitorID: f.monID, MonitorName: "m",
		IncidentID: f.incID, Kind: kind, ObservedAt: time.Now().UTC(),
	}
}

// One PENDING intent per verified+enabled bound channel; pending or
// disabled channels produce none.
func TestOutboxMigration(t *testing.T) {
	ctx := context.Background()
	c := conn(t)
	f := seedBase(t, c)
	good := mkChannel(t, c, f, "VERIFIED", true, true)
	mkChannel(t, c, f, "PENDING_VERIFICATION", false, true)
	mkChannel(t, c, f, "VERIFIED", false, true) // disabled

	tx, _ := c.Begin(ctx)
	intents, err := AppendTransitionDeliveries(ctx, tx, tinput(f, EventDown))
	if err != nil {
		t.Fatal(err)
	}
	tx.Commit(ctx)
	if len(intents) != 1 || intents[0].ChannelID != good {
		t.Fatalf("intents: %+v", intents)
	}
	var state, payload string
	if err := c.QueryRow(ctx, `
		SELECT state, safe_payload::text FROM uptime.notification_outbox
		WHERE channel_id=$1`, good).Scan(&state, &payload); err != nil {
		t.Fatal(err)
	}
	if state != "PENDING" {
		t.Fatalf("state %q", state)
	}
	// Privacy: no destination material or target URL in the projection.
	for _, secret := range []string{"ct", "chat", "token", "x.test"} {
		if strings.Contains(payload, secret) {
			t.Fatalf("safe_payload leaked %q: %s", secret, payload)
		}
	}
}

// Duplicate finalize re-derives the same event_key -> zero new rows.
func TestOutboxIdentity(t *testing.T) {
	ctx := context.Background()
	c := conn(t)
	f := seedBase(t, c)
	mkChannel(t, c, f, "VERIFIED", true, true)

	for i := 0; i < 2; i++ {
		tx, _ := c.Begin(ctx)
		if _, err := AppendTransitionDeliveries(ctx, tx, tinput(f, EventDown)); err != nil {
			t.Fatal(err)
		}
		tx.Commit(ctx)
	}
	var n int
	if err := c.QueryRow(ctx, `
		SELECT count(*) FROM uptime.notification_outbox WHERE incident_id=$1`,
		f.incID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("duplicate logical events: %d", n)
	}
}

// RECOVERY links its DOWN predecessor in the same stream.
func TestOutboxPredecessor(t *testing.T) {
	ctx := context.Background()
	c := conn(t)
	f := seedBase(t, c)
	mkChannel(t, c, f, "VERIFIED", true, true)

	tx, _ := c.Begin(ctx)
	downs, err := AppendTransitionDeliveries(ctx, tx, tinput(f, EventDown))
	if err != nil || len(downs) != 1 {
		t.Fatalf("down intents: %v %+v", err, downs)
	}
	recs, err := AppendTransitionDeliveries(ctx, tx, tinput(f, EventRecovery))
	if err != nil || len(recs) != 1 {
		t.Fatalf("recovery intents: %v %+v", err, recs)
	}
	tx.Commit(ctx)
	if recs[0].PredecessorID == nil || *recs[0].PredecessorID != downs[0].ID {
		t.Fatalf("predecessor not linked: %+v", recs[0])
	}
	// Recovery without any DOWN: null predecessor, still persists.
	f2 := seedBase(t, c)
	mkChannel(t, c, f2, "VERIFIED", true, true)
	tx, _ = c.Begin(ctx)
	orphan, err := AppendTransitionDeliveries(ctx, tx, tinput(f2, EventRecovery))
	if err != nil || len(orphan) != 1 {
		t.Fatal(err)
	}
	tx.Commit(ctx)
	if orphan[0].PredecessorID != nil {
		t.Fatal("orphan recovery fabricated a predecessor")
	}
}

// Cross-owner bindings are rejected by the schema; unverified and
// foreign channels never become intents.
func TestUnverifiedChannelRejected(t *testing.T) {
	ctx := context.Background()
	c := conn(t)
	f := seedBase(t, c)

	var other uuid.UUID
	if err := c.QueryRow(ctx, `
		INSERT INTO uptime.users(id,email,password_hash,status,monitor_limit)
		VALUES (gen_random_uuid(),$1,'x','ACTIVE',10) RETURNING id`,
		"oth+"+uuid.NewString()[:8]+"@test.invalid").Scan(&other); err != nil {
		t.Fatal(err)
	}
	var foreignChan uuid.UUID
	if err := c.QueryRow(ctx, `
		INSERT INTO uptime.notification_channels
		  (id,user_id,label,status,destination_ciphertext,encryption_key_version,
		   verified_at,verification_receipt,enabled)
		VALUES (gen_random_uuid(),$1,'f','VERIFIED','x',1,now(),'r',true)
		RETURNING id`, other).Scan(&foreignChan); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(ctx, `
		INSERT INTO uptime.monitor_channels(monitor_id,channel_id,user_id)
		VALUES ($1,$2,$3)`, f.monID, foreignChan, other); err == nil {
		t.Fatal("cross-owner binding accepted by schema")
	}

	tx, _ := c.Begin(ctx)
	intents, err := AppendTransitionDeliveries(ctx, tx, tinput(f, EventDown))
	if err != nil {
		t.Fatal(err)
	}
	tx.Commit(ctx)
	if len(intents) != 0 {
		t.Fatalf("cross-owner intent created: %+v", intents)
	}
}
