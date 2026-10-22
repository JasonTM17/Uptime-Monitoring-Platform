//go:build integration

package testsupport_test

// Restore-drill semantics (C81): the Go lane proves the invariants the
// operator script must preserve — clone a quiesced source into a fresh
// disposable database, reconcile before enabling, and prove revoked
// authority, outbox state, and row identity all survive honestly.
//
// CREATE DATABASE ... TEMPLATE is the physical-copy stand-in for
// pg_dump/pg_restore inside the test lane: same snapshot semantics,
// no external tooling in the test image. The operator path in
// scripts/restore-drill.mjs exercises real pg_dump and the manifest.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/auth"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/config"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/notification"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/testsupport"
)

func mustDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("TEST_DATABASE_URL is required (point it at the disposable postgres-test database)")
	}
	return dsn
}

func connTo(t *testing.T, db string) *pgx.Conn {
	t.Helper()
	cfg, err := pgx.ParseConfig(mustDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Database = db
	conn, err := pgx.ConnectConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("connect %s: %v", db, err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	return conn
}

func poolTo(t *testing.T, db string) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgx.ParseConfig(mustDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Database = db
	pool, err := pgxpool.New(context.Background(), cfg.ConnString())
	if err != nil {
		t.Fatalf("pool %s: %v", db, err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// cloneSource snapshots the test database into a fresh disposable
// database — the physical stand-in for dump+restore. The source must
// be quiesced (zero backends) exactly like the real drill requires.
func cloneSource(t *testing.T, srcDB, dst string) {
	t.Helper()
	admin := connTo(t, "postgres")
	ctx := context.Background()
	var n int
	if err := admin.QueryRow(ctx,
		`SELECT count(*) FROM pg_stat_activity WHERE datname=$1`, srcDB).
		Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("source database %s has %d live backends — quiesce before snapshot", srcDB, n)
	}
	if _, err := admin.Exec(ctx,
		fmt.Sprintf(`CREATE DATABASE %s TEMPLATE %s`, pgx.Identifier{dst}.Sanitize(), pgx.Identifier{srcDB}.Sanitize())); err != nil {
		t.Fatalf("clone: %v", err)
	}
	t.Cleanup(func() {
		dropDB(t, dst)
	})
}

func dropDB(t *testing.T, name string) {
	t.Helper()
	admin := connTo(t, "postgres")
	ctx := context.Background()
	admin.Exec(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1`, name)
	admin.Exec(ctx, fmt.Sprintf(`DROP DATABASE IF EXISTS %s`, pgx.Identifier{name}.Sanitize()))
}

func sourceDB(t *testing.T) string {
	t.Helper()
	cfg, err := pgx.ParseConfig(mustDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Database
}

// drillWorld is a deterministic dataset seeded into the source before
// cloning: one owner, one live session, one verified v1-ciphertext
// channel, one monitor with a completed run + result (a recent charge
// that must NOT be deleted or refunded), one INTERRUPTED run that must
// never gain a fabricated sample, an open incident, and a three-row
// causal outbox chain (DOWN pending -> RECOVERY leased-expired, plus a
// sent TEST row).
type drillWorld struct {
	userID, monID, chanID    uuid.UUID
	segID, runDone, runInt   uuid.UUID
	incidentID               uuid.UUID
	boxDown, boxRec, boxTest uuid.UUID
	token                    string
	v1cipher                 []byte
	v1material                    string
}

func seedWorld(t *testing.T, conn *pgx.Conn) drillWorld {
	t.Helper()
	ctx := context.Background()
	var w drillWorld
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	tok := base64.RawURLEncoding.EncodeToString(raw)
	w.token = tok
	w.v1material = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // 32 zero bytes, disposable

	if err := conn.QueryRow(ctx, `
		INSERT INTO uptime.users(id,email,password_hash,status,monitor_limit,security_version)
		VALUES (gen_random_uuid(),$1,'x','ACTIVE',100,1) RETURNING id`,
		"drill+"+uuid.NewString()[:8]+"@accept.invalid").Scan(&w.userID); err != nil {
		t.Fatalf("user: %v", err)
	}
	hash, err := auth.HashToken(w.token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO uptime.sessions(id,user_id,token_hash,security_version,
		  expires_at,idle_expires_at,device_label)
		VALUES (gen_random_uuid(),$1,$2,1,now()+interval '1 hour',
		  now()+interval '1 hour','drill-seed')`, w.userID, hash); err != nil {
		t.Fatalf("session: %v", err)
	}
	if err := conn.QueryRow(ctx, `
		INSERT INTO uptime.monitors(id,user_id,name,target_url,method,
		  interval_seconds,timeout_seconds,expected_status,next_check_at)
		VALUES (gen_random_uuid(),$1,'drill-mon','https://x.test','GET',60,5,NULL,now())
		RETURNING id`, w.userID).Scan(&w.monID); err != nil {
		t.Fatalf("monitor: %v", err)
	}
	ring, err := notification.ParseKeyring("1="+w.v1material, "1")
	if err != nil {
		t.Fatal(err)
	}
	chanID := uuid.New()
	w.v1cipher, _, err = ring.EncryptDestination([]byte("drill-chat-1"),
		notification.DestinationAAD(chanID, w.userID, 1))
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `
		INSERT INTO uptime.notification_channels(id,user_id,label,kind,status,
		  destination_ciphertext,destination_mask,encryption_key_version,
		  verified_at,verification_receipt,enabled)
		VALUES ($1,$2,'drill-chan','TELEGRAM','VERIFIED',$3,'***drill',1,now(),
		  'drill-receipt',true)
		RETURNING id`, chanID, w.userID, w.v1cipher).Scan(&w.chanID); err != nil {
		t.Fatalf("channel: %v", err)
	}
	if err := conn.QueryRow(ctx, `
		INSERT INTO uptime.schedule_segments(id,monitor_id,generation,
		  starts_at,interval_seconds)
		VALUES (gen_random_uuid(),$1,1,now()-interval '1 hour',60)
		RETURNING id`, w.monID).Scan(&w.segID); err != nil {
		t.Fatalf("segment: %v", err)
	}
	// A completed run WITH a result — the recent charge that restore
	// must preserve, never refund.
	if err := conn.QueryRow(ctx, `
		INSERT INTO uptime.check_runs(id,monitor_id,segment_id,slot_at,
		  generation,sequence,engine_epoch,status,finished_at)
		VALUES (gen_random_uuid(),$1,$2,now()-interval '5 minute',1,1,1,
		  'COMPLETED',now()-interval '5 minute')
		RETURNING id`, w.monID, w.segID).Scan(&w.runDone); err != nil {
		t.Fatalf("run done: %v", err)
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO uptime.check_results(check_id,monitor_id,outcome,
		  eligible,success,duration_ms,observed_at)
		VALUES ($1,$2,'SUCCESS',true,true,42,now()-interval '5 minute')`,
		w.runDone, w.monID); err != nil {
		t.Fatalf("result: %v", err)
	}
	// An interrupted run — it must stay evidence-free after restore.
	if err := conn.QueryRow(ctx, `
		INSERT INTO uptime.check_runs(id,monitor_id,segment_id,slot_at,
		  generation,sequence,engine_epoch,status,finished_at,terminal_reason)
		VALUES (gen_random_uuid(),$1,$2,now()-interval '4 minute',1,2,1,
		  'INTERRUPTED',now()-interval '4 minute','engine_takeover')
		RETURNING id`, w.monID, w.segID).Scan(&w.runInt); err != nil {
		t.Fatalf("run interrupted: %v", err)
	}
	if err := conn.QueryRow(ctx, `
		INSERT INTO uptime.incidents(id,monitor_id,opened_check_id,opened_at)
		VALUES (gen_random_uuid(),$1,$2,now()-interval '3 minute')
		RETURNING id`, w.monID, w.runDone).Scan(&w.incidentID); err != nil {
		t.Fatalf("incident: %v", err)
	}
	if err := conn.QueryRow(ctx, `
		INSERT INTO uptime.notification_outbox(id,user_id,monitor_id,
		  incident_id,channel_id,event_kind,event_key,channel_version,
		  safe_payload,state)
		VALUES (gen_random_uuid(),$1,$2,$3,$4,'DOWN',$5,1,'{}','PENDING')
		RETURNING id`, w.userID, w.monID, w.incidentID, w.chanID,
		"drill-down-"+uuid.NewString()[:8]).Scan(&w.boxDown); err != nil {
		t.Fatalf("box down: %v", err)
	}
	// RECOVERY leased mid-flight at snapshot time, lease already
	// expired — the reconcile step must reclaim it to PENDING.
	if err := conn.QueryRow(ctx, `
		INSERT INTO uptime.notification_outbox(id,user_id,monitor_id,
		  incident_id,channel_id,event_kind,event_key,predecessor_id,
		  channel_version,safe_payload,state,lease_token,lease_expires_at)
		VALUES (gen_random_uuid(),$1,$2,$3,$4,'RECOVERY',$5,$6,1,'{}',
		  'LEASED',gen_random_uuid(),now()-interval '1 minute')
		RETURNING id`, w.userID, w.monID, w.incidentID, w.chanID,
		"drill-rec-"+uuid.NewString()[:8], w.boxDown).Scan(&w.boxRec); err != nil {
		t.Fatalf("box rec: %v", err)
	}
	if err := conn.QueryRow(ctx, `
		INSERT INTO uptime.notification_outbox(id,user_id,monitor_id,
		  channel_id,event_kind,event_key,channel_version,safe_payload,
		  state,sent_at,attempts)
		VALUES (gen_random_uuid(),$1,$2,$3,'TEST',$4,1,'{}','SENT',
		  now()-interval '2 minute',1)
		RETURNING id`, w.userID, w.monID, w.chanID,
		"drill-test-"+uuid.NewString()[:8]).Scan(&w.boxTest); err != nil {
		t.Fatalf("box test: %v", err)
	}
	return w
}

// TestRestoreCounts clones the quiesced source and proves the snapshot
// carried every canonical table plus seeded fixtures — counts equal,
// zero FK orphans, interrupted runs keep zero fabricated results, and
// the schema version is identical (the manifest's wantSchema).
func TestRestoreCounts(t *testing.T) {
	src := sourceDB(t)
	conn := connTo(t, src)
	ctx := context.Background()

	w := seedWorld(t, conn)
	counts := map[string]int{}
	for _, tbl := range testsupport.CanonicalTables {
		var n int
		if err := conn.QueryRow(ctx,
			fmt.Sprintf(`SELECT count(*) FROM uptime.%s`, pgx.Identifier{tbl}.Sanitize())).
			Scan(&n); err != nil {
			t.Fatalf("count %s: %v", tbl, err)
		}
		counts[tbl] = n
	}
	var schemaVersion int64
	if err := conn.QueryRow(ctx,
		`SELECT max(version) FROM schema_migrations`).Scan(&schemaVersion); err != nil {
		t.Fatal(err)
	}
	// A manifest receipt from this source must validate; corrupt or
	// wrong-version receipts must refuse before any mutation.
	good := fmt.Sprintf(`{"format":%q,"schema_version":%d,"created_at":%q,"source_db":%q,"pg_dump_version":"17.11","dump_sha256":%q,"tables":%d}`,
		testsupport.DrillFormat, schemaVersion, time.Now().UTC().Format(time.RFC3339),
		src, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", len(testsupport.CanonicalTables))
	if _, err := testsupport.ValidateManifest([]byte(good), schemaVersion); err != nil {
		t.Fatalf("good manifest rejected: %v", err)
	}
	if _, err := testsupport.ValidateManifest([]byte(`{corrupt`), schemaVersion); err == nil {
		t.Fatal("corrupt manifest accepted")
	}
	if _, err := testsupport.ValidateManifest([]byte(good), schemaVersion+1); err == nil {
		t.Fatal("wrong-version manifest accepted")
	}
	if _, err := testsupport.ValidateManifest([]byte(
		`{"format":"pg-dump","schema_version":1,"created_at":"2026-01-01T00:00:00Z","source_db":"x","dump_sha256":"`+
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"+`"}`),
		schemaVersion); err == nil {
		t.Fatal("foreign-format manifest accepted")
	}
	conn.Close(ctx)

	dst := "drill_counts_" + uuid.NewString()[:8]
	cloneSource(t, src, dst)
	rc := connTo(t, dst)

	for _, tbl := range testsupport.CanonicalTables {
		var n int
		if err := rc.QueryRow(ctx,
			fmt.Sprintf(`SELECT count(*) FROM uptime.%s`, pgx.Identifier{tbl}.Sanitize())).
			Scan(&n); err != nil {
			t.Fatalf("clone count %s: %v", tbl, err)
		}
		if n != counts[tbl] {
			t.Fatalf("table %s: clone %d != source %d", tbl, n, counts[tbl])
		}
	}
	var cloneSchema int64
	rc.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&cloneSchema)
	if cloneSchema != schemaVersion {
		t.Fatalf("schema version drift: %d -> %d", schemaVersion, cloneSchema)
	}

	// FK-integrity sweep: zero orphans across the drill relations.
	orphanSQL := []string{
		`SELECT count(*) FROM uptime.sessions s WHERE NOT EXISTS (SELECT 1 FROM uptime.users u WHERE u.id=s.user_id)`,
		`SELECT count(*) FROM uptime.monitors m WHERE NOT EXISTS (SELECT 1 FROM uptime.users u WHERE u.id=m.user_id)`,
		`SELECT count(*) FROM uptime.check_runs r WHERE NOT EXISTS (SELECT 1 FROM uptime.monitors m WHERE m.id=r.monitor_id)`,
		`SELECT count(*) FROM uptime.check_results c WHERE NOT EXISTS (SELECT 1 FROM uptime.check_runs r WHERE r.id=c.check_id AND r.monitor_id=c.monitor_id)`,
		`SELECT count(*) FROM uptime.notification_outbox o LEFT JOIN uptime.notification_outbox p ON o.predecessor_id=p.id WHERE o.predecessor_id IS NOT NULL AND p.id IS NULL`,
	}
	for i, q := range orphanSQL {
		var n int
		if err := rc.QueryRow(ctx, q).Scan(&n); err != nil {
			t.Fatalf("orphan check %d: %v", i, err)
		}
		if n != 0 {
			t.Fatalf("orphan check %d: %d dangling rows", i, n)
		}
	}
	// The interrupted run carries no fabricated sample; the completed
	// charge is preserved unchanged.
	var fab, charge int
	rc.QueryRow(ctx, `SELECT count(*) FROM uptime.check_results WHERE check_id=$1`, w.runInt).Scan(&fab)
	rc.QueryRow(ctx, `SELECT count(*) FROM uptime.check_results WHERE check_id=$1 AND duration_ms=42`, w.runDone).Scan(&charge)
	if fab != 0 || charge != 1 {
		t.Fatalf("restore fabricated %d samples / lost charge=%d", fab, charge)
	}
	var runStatus string
	rc.QueryRow(ctx, `SELECT status FROM uptime.check_runs WHERE id=$1`, w.runInt).Scan(&runStatus)
	if runStatus != "INTERRUPTED" {
		t.Fatalf("interrupted run became %q", runStatus)
	}
}

// Restored sessions must not ride into the new world: the drill bumps
// every user's security_version, so the real LookupSession path —
// the same predicate the middleware enforces — rejects the old token.
// A session stamped at the new version works (new authority only).
func TestRestoredAuthorityRevocation(t *testing.T) {
	src := sourceDB(t)
	conn := connTo(t, src)
	w := seedWorld(t, conn)
	conn.Close(context.Background())

	dst := "drill_auth_" + uuid.NewString()[:8]
	cloneSource(t, src, dst)
	pool := poolTo(t, dst)
	ctx := context.Background()

	cfg := config.AuthConfig{
		SessionAbsoluteExpiry:      8 * time.Hour,
		SessionIdleExpiry:          30 * time.Minute,
		LoginIPAttemptsPerMin:      60,
		LoginAccountAttemptsPer15M: 10,
		RegisterIPAttemptsPerMin:   60,
		LimiterMaxKeys:             10000,
		ArgonMemoryKiB:             4096, ArgonTime: 1, ArgonParallelism: 1,
		ArgonSaltLen: 16, ArgonKeyLen: 32, HashWorkers: 1,
	}
	repo := auth.NewRepository(pool, 5*time.Second)
	svc := auth.NewService(repo, auth.NewHasher(cfg), cfg, 100)

	// Pre-revocation the restored token authenticates — the session
	// really did travel with the snapshot.
	if _, err := svc.LookupSession(ctx, w.token); err != nil {
		t.Fatalf("restored session rejected pre-revocation: %v", err)
	}
	// The drill's revoke step: bump every owner's security epoch.
	if _, err := pool.Exec(ctx,
		`UPDATE uptime.users SET security_version=security_version+1`); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.LookupSession(ctx, w.token); err == nil {
		t.Fatal("revoked-by-restore session still authenticates")
	} else if !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatalf("expected ErrInvalidSession, got %v", err)
	}
	// A session stamped at the NEW version is the only authority.
	raw2 := make([]byte, 32)
	if _, err := rand.Read(raw2); err != nil {
		t.Fatal(err)
	}
	newTok := base64.RawURLEncoding.EncodeToString(raw2)
	hash, _ := auth.HashToken(newTok)
	if _, err := pool.Exec(ctx, `
		INSERT INTO uptime.sessions(id,user_id,token_hash,security_version,
		  expires_at,idle_expires_at,device_label)
		VALUES (gen_random_uuid(),$1,$2,2,now()+interval '1 hour',
		  now()+interval '1 hour','post-restore')`, w.userID, hash); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.LookupSession(ctx, newTok); err != nil {
		t.Fatalf("new-version session rejected: %v", err)
	}
}

// Outbox reconciliation: the snapshot froze a leased mid-flight row.
// The drill's pre-enable reconcile reclaims expired leases to PENDING,
// keeps the causal predecessor chain, and never fabricates delivery.
func TestRestoredOutboxReconciliation(t *testing.T) {
	src := sourceDB(t)
	conn := connTo(t, src)
	ctx := context.Background()
	w := seedWorld(t, conn)
	conn.Close(ctx)

	dst := "drill_outbox_" + uuid.NewString()[:8]
	cloneSource(t, src, dst)
	rc := connTo(t, dst)

	// Pre-reconcile snapshot scoped to the seeded owner: one PENDING,
	// one expired-LEASED, one SENT (other tests' rows share this DB).
	var pending, leased, sent int
	rc.QueryRow(ctx, `SELECT count(*) FROM uptime.notification_outbox WHERE state='PENDING' AND user_id=$1`, w.userID).Scan(&pending)
	rc.QueryRow(ctx, `SELECT count(*) FROM uptime.notification_outbox WHERE state='LEASED' AND user_id=$1`, w.userID).Scan(&leased)
	rc.QueryRow(ctx, `SELECT count(*) FROM uptime.notification_outbox WHERE state='SENT' AND user_id=$1`, w.userID).Scan(&sent)
	if leased != 1 {
		t.Fatalf("snapshot lost the leased row: %d", leased)
	}

	// The documented pre-enable reconcile — identical to the runbook
	// and the script's SQL: expired leases return to PENDING.
	// The reconcile is deliberately global — in a quiesced world every
	// expired lease returns to PENDING (leftover rows from other tests
	// share this disposable DB and are reclaimed too).
	tag, err := rc.Exec(ctx, `
		UPDATE uptime.notification_outbox
		SET state='PENDING', lease_token=NULL, lease_expires_at=NULL,
		    version=version+1
		WHERE state='LEASED' AND lease_expires_at < now()`)
	if err != nil {
		t.Fatal(err)
	}
	if tag.RowsAffected() < 1 {
		t.Fatalf("reconcile reclaimed %d rows, want >=1", tag.RowsAffected())
	}
	var minePending int
	rc.QueryRow(ctx, `SELECT count(*) FROM uptime.notification_outbox
		WHERE id=$1 AND state='PENDING' AND lease_token IS NULL`, w.boxRec).
		Scan(&minePending)
	if minePending != 1 {
		t.Fatal("seeded leased row not reclaimed to PENDING")
	}

	// Deliverable set = original pending + reclaimed lease; the causal
	// chain still points at its DOWN predecessor; nothing was sent.
	var deliverable, predOK, sentNow, total int
	rc.QueryRow(ctx, `SELECT count(*) FROM uptime.notification_outbox WHERE state='PENDING' AND user_id=$1`, w.userID).Scan(&deliverable)
	rc.QueryRow(ctx, `SELECT count(*) FROM uptime.notification_outbox
		WHERE id=$1 AND predecessor_id=$2`, w.boxRec, w.boxDown).Scan(&predOK)
	rc.QueryRow(ctx, `SELECT count(*) FROM uptime.notification_outbox WHERE state='SENT' AND user_id=$1`, w.userID).Scan(&sentNow)
	rc.QueryRow(ctx, `SELECT count(*) FROM uptime.notification_outbox WHERE user_id=$1`, w.userID).Scan(&total)
	if deliverable != pending+leased {
		t.Fatalf("deliverable %d, want pending %d + reclaimed %d", deliverable, pending, leased)
	}
	if predOK != 1 {
		t.Fatal("causal predecessor chain broken by restore")
	}
	if sentNow != sent {
		t.Fatalf("delivery fabricated: sent %d -> %d", sent, sentNow)
	}
	if total != 3 {
		t.Fatalf("row count drifted: %d", total)
	}

	// The restored v1 ciphertext still reads under a rotated
	// (v1-read + v2-write) ring — the dual-read contract travels with
	// the data, and new writes would seal under v2.
	dual, err := notification.ParseKeyring("1="+w.v1material+",2="+"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=", "2")
	if err != nil {
		t.Fatal(err)
	}
	var ct []byte
	var kv int
	rc.QueryRow(ctx, `SELECT destination_ciphertext, encryption_key_version
		FROM uptime.notification_channels WHERE id=$1`, w.chanID).Scan(&ct, &kv)
	pt, err := dual.DecryptDestination(kv, ct, notification.DestinationAAD(w.chanID, w.userID, 1))
	if err != nil || string(pt) != "drill-chat-1" {
		t.Fatalf("restored ciphertext unreadable: %v", err)
	}
}
