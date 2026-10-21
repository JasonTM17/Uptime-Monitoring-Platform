//go:build integration

package notification

// C48 — deterministic provider/ACK/crash fault schedules over a real
// dispatcher and real lease queries. The contract under test is
// bounded at-least-once: a durable intent is never lost; a lost ACK
// may duplicate the EXTERNAL provider message but never the logical
// event (one row, one event_key); a SENT row never replays.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// recordingSender is the provider barrier: it records every external
// send so the schedules can count provider-side messages
// independently of local delivery state.
type recordingSender struct {
	mu    sync.Mutex
	calls []sendCall
	err   error
}

type sendCall struct{ token, chatID, text string }

func (s *recordingSender) Send(_ context.Context, token, chatID,
	text string) (Delivery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, sendCall{token, chatID, text})
	return Delivery{ProviderMessageID: int64(len(s.calls))}, s.err
}

func (s *recordingSender) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func (s *recordingSender) last() sendCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[len(s.calls)-1]
}

// deliverableChannel upgrades a mkChannel row to a real decryptable
// destination — the dispatcher's recipient fence decrypts the live
// row, so the fixture "ct" bytes would only exercise suppression.
func deliverableChannel(t *testing.T, c *pgx.Conn, f fixture,
	ring *Keyring) uuid.UUID {
	t.Helper()
	ch := mkChannel(t, c, f, "VERIFIED", true, true)
	ct, kv, err := ring.EncryptDestination([]byte("424242"),
		DestinationAAD(ch, f.userID, ring.WriteVersion()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(context.Background(), `
		UPDATE uptime.notification_channels
		SET destination_ciphertext=$2, encryption_key_version=$3
		WHERE id=$1`, ch, ct, kv); err != nil {
		t.Fatal(err)
	}
	return ch
}

func disp(t *testing.T, c *pgx.Conn, ring *Keyring,
	s *recordingSender) *Dispatcher {
	t.Helper()
	return NewDispatcher(c, nil, ring, s, DispatcherConfig{
		Lease:       testLease,
		Retry:       DefaultRetryPolicy,
		SendTimeout: 2 * time.Second,
		TickEvery:   time.Minute,
		BotToken:    "dummy",
	}, nil)
}

func claimsOf(t *testing.T, c *pgx.Conn) []Claim {
	t.Helper()
	cl, err := ClaimDue(context.Background(), c, testLease)
	if err != nil {
		t.Fatal(err)
	}
	return cl
}

// expireLease simulates the crash boundary: the lease clock runs out
// with no disposition persisted.
func expireLease(t *testing.T, c *pgx.Conn, id uuid.UUID) {
	t.Helper()
	if _, err := c.Exec(context.Background(), `
		UPDATE uptime.notification_outbox
		SET lease_expires_at=clock_timestamp()-interval '1s'
		WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
}

// Crash before send: the claim commits the lease but no send or
// disposition happens. Reclaim returns the intent; a restarted
// dispatcher delivers it exactly once.
func TestCrashBeforeSend(t *testing.T) {
	c := conn(t)
	cleanOutbox(t, c)
	f := seedBase(t, c)
	ring := testRing(t, 1, 11)
	ch := deliverableChannel(t, c, f, ring)
	row := seedOutbox(t, c, f, ch, "DOWN", nil, "PENDING")

	cl := claimsOf(t, c)
	if len(cl) != 1 || cl[0].ID != row {
		t.Fatalf("claim: %+v", cl)
	}
	if st := stateOf(t, c, row); st != "LEASED" {
		t.Fatalf("state %s", st)
	}
	// crash — no send, no disposition, lease dies.

	expireLease(t, c, row)
	if n, err := ReclaimExpired(context.Background(), c, testLease); err != nil || n != 1 {
		t.Fatalf("reclaim n=%d err=%v", n, err)
	}
	if st := stateOf(t, c, row); st != "PENDING" {
		t.Fatalf("state %s", st)
	}

	snd := &recordingSender{}
	d := disp(t, c, ring, snd)
	cl = claimsOf(t, c)
	if len(cl) != 1 {
		t.Fatalf("re-claim: %d", len(cl))
	}
	d.process(context.Background(), cl[0])

	if snd.count() != 1 {
		t.Fatalf("provider sends %d", snd.count())
	}
	if st := stateOf(t, c, row); st != "SENT" {
		t.Fatalf("state %s", st)
	}
	l := snd.last()
	if l.token != "dummy" || l.chatID != "424242" {
		t.Fatalf("provider gate: %+v", l)
	}
	if strings.Contains(l.text, "dummy") {
		t.Fatal("secret leaked into message text")
	}
}

// Send succeeds at the provider but the local ACK never commits
// (the connection dies between send and ACK). The lease expires,
// reclaim returns the row, and a restarted dispatcher re-delivers:
// one logical row, two external sends — the honest duplicate an
// at-least-once pipeline owes the recipient.
func TestSendSuccessAckLoss(t *testing.T) {
	c := conn(t)
	cleanOutbox(t, c)
	f := seedBase(t, c)
	ring := testRing(t, 1, 13)
	ch := deliverableChannel(t, c, f, ring)
	row := seedOutbox(t, c, f, ch, "DOWN", nil, "PENDING")

	snd := &recordingSender{}
	d := disp(t, c, ring, snd)
	cl := claimsOf(t, c)
	if len(cl) != 1 {
		t.Fatalf("claim %d", len(cl))
	}

	// The send commits at the provider — then the process dies
	// before ackFn. The row stays LEASED with no disposition.
	gate, err := d.revalidate(context.Background(), cl[0])
	if err != nil || !gate.Deliverable || gate.ChatID == "" {
		t.Fatalf("gate: %+v %v", gate, err)
	}
	if _, err := d.sender.Send(context.Background(), d.cfg.BotToken,
		gate.ChatID, renderText(cl[0])); err != nil {
		t.Fatal(err)
	}
	if st := stateOf(t, c, row); st != "LEASED" {
		t.Fatalf("state %s", st)
	}

	expireLease(t, c, row)
	if n, err := ReclaimExpired(context.Background(), c, testLease); err != nil || n != 1 {
		t.Fatalf("reclaim n=%d err=%v", n, err)
	}

	// Restart: a fresh dispatcher re-claims and re-sends the same row.
	d2 := disp(t, conn(t), ring, snd)
	cl = claimsOf(t, c)
	if len(cl) != 1 {
		t.Fatalf("re-claim %d", len(cl))
	}
	d2.process(context.Background(), cl[0])

	if snd.count() != 2 {
		t.Fatalf("want 2 external sends for 1 logical event, got %d",
			snd.count())
	}
	if st := stateOf(t, c, row); st != "SENT" {
		t.Fatalf("state %s", st)
	}
	var n int
	if err := c.QueryRow(context.Background(), `
		SELECT count(*) FROM uptime.notification_outbox
		WHERE event_key=(SELECT event_key FROM uptime.notification_outbox
		                 WHERE id=$1)`, row).Scan(&n); err != nil || n != 1 {
		t.Fatalf("logical rows n=%d err=%v", n, err)
	}
}

// Crash after ACK: the disposition is durable before the process
// dies. A restarted dispatcher must never replay a SENT row.
func TestCrashAfterAck(t *testing.T) {
	c := conn(t)
	cleanOutbox(t, c)
	f := seedBase(t, c)
	ring := testRing(t, 1, 17)
	ch := deliverableChannel(t, c, f, ring)
	row := seedOutbox(t, c, f, ch, "DOWN", nil, "PENDING")

	snd := &recordingSender{}
	d := disp(t, c, ring, snd)
	cl := claimsOf(t, c)
	if len(cl) != 1 {
		t.Fatalf("claim %d", len(cl))
	}
	d.process(context.Background(), cl[0])
	if st := stateOf(t, c, row); st != "SENT" || snd.count() != 1 {
		t.Fatalf("state %s sends %d", st, snd.count())
	}
	// crash — after the ACK committed.

	// Restart on a fresh conn: nothing due, nothing replayed.
	c2 := conn(t)
	d2 := disp(t, c2, ring, snd)
	if n, err := d2.Tick(context.Background()); err != nil || n != 0 {
		t.Fatalf("tick n=%d err=%v", n, err)
	}
	if snd.count() != 1 {
		t.Fatalf("SENT row replayed: %d sends", snd.count())
	}
}

// Restart ordering: a DEAD predecessor still blocks its RECOVERY
// across dispatcher restarts; once the head is resolved (here the
// authorized skip) the recovery proceeds. A channel disabled between
// claim and send is suppressed by the live recipient fence — the
// authorized skip, never a send to a revoked destination.
func TestDispatcherRestartOrdering(t *testing.T) {
	ctx := context.Background()
	c := conn(t)
	cleanOutbox(t, c)
	f := seedBase(t, c)
	ring := testRing(t, 1, 19)
	ch := deliverableChannel(t, c, f, ring)

	down := seedOutbox(t, c, f, ch, "DOWN", nil, "DEAD")
	rec := seedOutbox(t, c, f, ch, "RECOVERY", &down, "PENDING")

	snd := &recordingSender{}
	d := disp(t, c, ring, snd)
	if n, err := d.Tick(ctx); err != nil || n != 0 {
		t.Fatalf("tick n=%d err=%v", n, err)
	}
	if st := stateOf(t, c, rec); st != "PENDING" {
		t.Fatal("recovery escaped dead head")
	}
	if snd.count() != 0 {
		t.Fatal("sent behind a dead head")
	}

	// Second stream whose channel is disabled mid-lease.
	f2 := seedBase(t, c)
	ch2 := deliverableChannel(t, c, f2, ring)
	revoked := seedOutbox(t, c, f2, ch2, "DOWN", nil, "PENDING")

	// Resolve the dead head honestly (the authorized skip). The
	// skip cascades: a suppressed DOWN never releases its RECOVERY
	// to send — a channel that never learned "down" must never hear
	// "recovered". The restarted dispatcher claims only the second
	// stream's row.
	if _, err := c.Exec(ctx, `
		UPDATE uptime.notification_outbox SET state='SUPPRESSED'
		WHERE id=$1`, down); err != nil {
		t.Fatal(err)
	}
	c2 := conn(t)
	d2 := disp(t, c2, ring, snd)
	cl := claimsOf(t, c2)
	if len(cl) != 1 {
		t.Fatalf("claims %d", len(cl))
	}
	if st := stateOf(t, c, rec); st != "SUPPRESSED" {
		t.Fatalf("cascade left recovery %s", st)
	}

	// Revoke the channel after the lease committed — the recipient
	// fence revalidates immediately before send.
	if _, err := c.Exec(ctx, `
		UPDATE uptime.notification_channels
		SET status='DISABLED', enabled=false WHERE id=$1`, ch2); err != nil {
		t.Fatal(err)
	}
	for _, row := range cl {
		if err := d2.process(ctx, row); err != nil {
			t.Fatal(err)
		}
	}

	if st := stateOf(t, c, rec); st != "SUPPRESSED" {
		t.Fatalf("recovery state %s", st)
	}
	if st := stateOf(t, c, revoked); st != "SUPPRESSED" {
		t.Fatalf("revoked state %s", st)
	}
	if snd.count() != 0 {
		t.Fatalf("provider sends %d — suppressed streams must not send",
			snd.count())
	}
}
