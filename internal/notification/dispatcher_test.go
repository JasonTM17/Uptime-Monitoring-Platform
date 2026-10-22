package notification

import (
	"context"
	"errors"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// fakeClock is the deterministic time source.
type fakeClock struct{ now time.Time }

func (f *fakeClock) Now() time.Time          { return f.now }
func (f *fakeClock) Advance(d time.Duration) { f.now = f.now.Add(d) }

// fakeSender records sends and serves scripted outcomes.
type fakeSender struct {
	calls  []string
	script func(call int) (Delivery, error)
	n      int
}

func (f *fakeSender) Send(ctx context.Context, token, chatID,
	text string) (Delivery, error) {
	f.calls = append(f.calls, chatID)
	f.n++
	if f.script != nil {
		return f.script(f.n)
	}
	return Delivery{ProviderMessageID: int64(f.n)}, nil
}

// fakeStore scripts the claim/ack/reschedule/suppress/dead seams and
// records every disposition.
type fakeStore struct {
	claims  []Claim
	claimN  int
	acked   []uuid.UUID
	resched map[uuid.UUID]int
	supp    map[uuid.UUID]string
	dead    map[uuid.UUID]string
	gates   map[uuid.UUID]RecipientGate
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		resched: map[uuid.UUID]int{}, supp: map[uuid.UUID]string{},
		dead: map[uuid.UUID]string{}, gates: map[uuid.UUID]RecipientGate{},
	}
}

func (f *fakeStore) wire(d *Dispatcher) {
	d.claimFn = func(ctx context.Context) ([]Claim, error) {
		f.claimN++
		if f.claimN > 1 || len(f.claims) == 0 {
			return nil, ErrClaimClosed
		}
		return f.claims, nil
	}
	d.revalidate = func(ctx context.Context, c Claim) (RecipientGate, error) {
		g, ok := f.gates[c.ID]
		if !ok {
			return RecipientGate{Deliverable: true, VersionOK: true,
				OwnerActive: true, ChatID: "111"}, nil
		}
		return g, nil
	}
	d.ackFn = func(ctx context.Context, id, tok uuid.UUID) (bool, error) {
		f.acked = append(f.acked, id)
		return true, nil
	}
	d.reschedFn = func(ctx context.Context, id, tok uuid.UUID,
		next time.Time, code string, max int) (Disposition, error) {
		f.resched[id]++
		return DispositionPending, nil
	}
	d.suppressFn = func(ctx context.Context, id, tok uuid.UUID,
		reason string) (bool, error) {
		f.supp[id] = reason
		return true, nil
	}
	d.deadFn = func(ctx context.Context, id, tok uuid.UUID,
		code string) (bool, error) {
		f.dead[id] = code
		return true, nil
	}
}

func testDispatcher(fs *fakeStore, snd Sender, clk *fakeClock) *Dispatcher {
	d := &Dispatcher{
		cfg: DispatcherConfig{
			Lease: LeaseConfig{Batch: 10, LeaseFor: time.Minute,
				MaxAttempts: 3},
			Retry:       DefaultRetryPolicy,
			SendTimeout: 5 * time.Second,
			TickEvery:   time.Millisecond,
			BotToken:    "dummy",
		},
		sender: snd, clock: clk,
		rng: rand.New(rand.NewPCG(42, 43)),
	}
	fs.wire(d)
	return d
}

func mkClaim(kind string, seq int) Claim {
	return Claim{
		ID: uuid.New(), MonitorID: uuid.New(), UserID: uuid.New(),
		ChannelID: uuid.New(), EventKind: kind, ChannelVersion: 1,
		LeaseToken: uuid.New(), Attempts: 1,
		CreatedAt:   time.Now(),
		SafePayload: []byte(`{"monitor_name":"m"}`),
	}
}

// A transient fence failure is not an eligibility verdict: the row
// stays recoverable (never SUPPRESSED), the tick does not count it,
// and the failure surfaces through LastErr.
func TestTransientRevalidateKeepsRow(t *testing.T) {
	fs := newFakeStore()
	d := testDispatcher(fs, &fakeSender{n: 1}, &fakeClock{})
	cl := mkClaim("DOWN", 1)
	fs.claims = []Claim{cl}
	d.revalidate = func(ctx context.Context, c Claim) (RecipientGate, error) {
		return RecipientGate{}, errors.New("db hiccup")
	}
	n, err := d.Tick(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("transient failure counted as disposition")
	}
	if _, ok := fs.supp[cl.ID]; ok {
		t.Fatal("transient error terminalized the row")
	}
	if d.LastErr() == nil {
		t.Fatal("failure not surfaced via LastErr")
	}
}

// A recipient row gone entirely is a genuine skip — suppress fires
// with recipient_gone and the tick counts the disposition.
func TestGoneRecipientSuppresses(t *testing.T) {
	fs := newFakeStore()
	d := testDispatcher(fs, &fakeSender{n: 1}, &fakeClock{})
	cl := mkClaim("DOWN", 1)
	fs.claims = []Claim{cl}
	d.revalidate = func(ctx context.Context, c Claim) (RecipientGate, error) {
		return RecipientGate{}, pgx.ErrNoRows
	}
	n, err := d.Tick(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if fs.supp[cl.ID] != "recipient_gone" {
		t.Fatalf("supp=%q", fs.supp[cl.ID])
	}
}

// 429's provider-supplied retry_after is honored but clamped to the
// retry policy ceiling; base backoff is exponential min*2^(n-1).
func TestRetryAfterBound(t *testing.T) {
	p := DefaultRetryPolicy
	r := rand.New(rand.NewPCG(1, 1))
	if d := ComputeRetry(1, 0, p, r); d < p.MinDelay-200*time.Millisecond ||
		d > p.MinDelay+time.Second {
		t.Fatalf("attempt1 delay %v", d)
	}
	// Provider asks 10 minutes — honored (within ceiling).
	if d := ComputeRetry(1, 10*time.Minute, p, nil); d != 10*time.Minute {
		t.Fatalf("retry_after %v", d)
	}
	// Provider asks an hour — clamped to the 15m ceiling.
	if d := ComputeRetry(1, time.Hour, p, nil); d != p.MaxDelay {
		t.Fatalf("clamped %v", d)
	}
	// Exponential grows and saturates at the ceiling.
	prev := time.Duration(0)
	for a := 1; a < 10; a++ {
		d := ComputeRetry(a, 0, p, nil)
		if d > p.MaxDelay || d < prev {
			t.Fatalf("attempt %d delay %v prev %v", a, d, prev)
		}
		prev = d
	}
}

// Claims process in claim order; a retryable failure reschedules
// instead of consuming.
func TestOrderedDispatch(t *testing.T) {
	fs := newFakeStore()
	down, rec := mkClaim("DOWN", 1), mkClaim("RECOVERY", 2)
	fs.claims = []Claim{down, rec}
	snd := &fakeSender{}
	clk := &fakeClock{now: time.Now()}
	d := testDispatcher(fs, snd, clk)

	n, err := d.Tick(context.Background())
	if err != nil || n != 2 {
		t.Fatalf("tick %d %v", n, err)
	}
	if len(fs.acked) != 2 || fs.acked[0] != down.ID || fs.acked[1] != rec.ID {
		t.Fatalf("order %+v", fs.acked)
	}
	if len(snd.calls) != 2 {
		t.Fatalf("sends %v", snd.calls)
	}
}

// Permanent provider failures go DEAD; retryables reschedule until
// the attempts budget exhausts.
func TestRetryBudget(t *testing.T) {
	fs := newFakeStore()
	cl := mkClaim("DOWN", 1)
	cl.Attempts = 8 // at the policy ceiling
	fs.claims = []Claim{cl}
	snd := &fakeSender{script: func(int) (Delivery, error) {
		return Delivery{}, retryablef("provider 500")
	}}
	d := testDispatcher(fs, snd, &fakeClock{now: time.Now()})
	if _, err := d.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fs.dead[cl.ID] != "RETRY_EXHAUSTED" {
		t.Fatalf("expected DEAD, got resched=%d dead=%v",
			fs.resched[cl.ID], fs.dead)
	}

	// Permanent rejection goes straight to DEAD.
	fs2 := newFakeStore()
	cl2 := mkClaim("DOWN", 1)
	fs2.claims = []Claim{cl2}
	snd2 := &fakeSender{script: func(int) (Delivery, error) {
		return Delivery{}, permanentf("bot blocked")
	}}
	d2 := testDispatcher(fs2, snd2, &fakeClock{now: time.Now()})
	if _, err := d2.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fs2.dead[cl2.ID] != "PERMANENT" {
		t.Fatalf("expected PERMANENT dead, got %v", fs2.dead)
	}
	if len(fs2.acked) != 0 {
		t.Fatal("permanent acked")
	}
}

// A channel disabled or version-changed between claim and send is
// SUPPRESSED — the authorized skip, never a send attempt.
func TestRecipientVersionFence(t *testing.T) {
	fs := newFakeStore()
	stale := mkClaim("DOWN", 1)
	disabled := mkClaim("DOWN", 2)
	fs.claims = []Claim{stale, disabled}
	fs.gates[stale.ID] = RecipientGate{Deliverable: true, VersionOK: false,
		OwnerActive: true, ChatID: "1"}
	fs.gates[disabled.ID] = RecipientGate{Deliverable: false, VersionOK: true,
		OwnerActive: true}
	snd := &fakeSender{}
	d := testDispatcher(fs, snd, &fakeClock{now: time.Now()})
	if _, err := d.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(snd.calls) != 0 {
		t.Fatalf("ineligible sends happened: %v", snd.calls)
	}
	if fs.supp[stale.ID] == "" || fs.supp[disabled.ID] == "" {
		t.Fatalf("suppressions %+v", fs.supp)
	}
}

// Cancellation between claims stops the pass — no send begins, and
// remaining claims keep their leases (recoverable by expiry).
func TestDispatcherCancellation(t *testing.T) {
	fs := newFakeStore()
	fs.claims = []Claim{mkClaim("DOWN", 1), mkClaim("DOWN", 2)}
	snd := &fakeSender{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := testDispatcher(fs, snd, &fakeClock{now: time.Now()})
	n, err := d.Tick(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("tick %d %v", n, err)
	}
	if len(snd.calls) != 0 {
		t.Fatal("send happened under canceled ctx")
	}
}

// Limiter: global and per-chat bounds actually gate sends; window
// refill under fake clock restores them.
func TestDispatcherRateLimit(t *testing.T) {
	fs := newFakeStore()
	fs.claims = []Claim{mkClaim("DOWN", 1), mkClaim("DOWN", 2)}
	snd := &fakeSender{}
	clk := &fakeClock{now: time.Now()}
	d := testDispatcher(fs, snd, clk)
	d.limit = NewLimiter(1, 1, clk) // 1/sec global, 1/sec per chat

	if _, err := d.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Two claims but only the first chat burst fits — second is
	// rescheduled, not failed.
	if len(snd.calls) != 1 {
		t.Fatalf("sends %d want 1 (limiter)", len(snd.calls))
	}
	if len(fs.resched) != 1 {
		t.Fatalf("resched %+v", fs.resched)
	}
	if len(fs.acked) != 1 {
		t.Fatalf("acked %+v", fs.acked)
	}
}

// A refusal must still bank the accumulated refill — polling the
// limiter faster than the refill rate must converge on a full token,
// not discard the increment each call.
func TestLimiterRefusalKeepsRefill(t *testing.T) {
	clk := &fakeClock{now: time.Now()}
	l := NewLimiter(-1, 1, clk) // global disabled, 1 token/sec per chat
	chat := uuid.New()

	if !l.Allow(chat) {
		t.Fatal("first send should be allowed")
	}
	// Second immediate send refused; then 3 polls at +400ms must
	// bank 0.4+0.4+0.4 => cap at 1 -> third poll allows.
	if l.Allow(chat) {
		t.Fatal("immediate resend should be refused")
	}
	for i := 0; i < 2; i++ {
		clk.Advance(400 * time.Millisecond)
		if l.Allow(chat) {
			t.Fatalf("poll %d allowed too early — refill not banking", i)
		}
	}
	clk.Advance(400 * time.Millisecond)
	if !l.Allow(chat) {
		t.Fatal("refill must accumulate across refusals")
	}
}
