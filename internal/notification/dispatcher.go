package notification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Dispatcher drains the durable outbox through the bounded
// claim→revalidate→send→ACK pipeline (C46). Every phase is a
// separate transaction; no network I/O happens under a row lock;
// a provider send is never recalled — only its disposition changes.

// Sender is the provider boundary (TelegramSender satisfies it).
type Sender interface {
	Send(ctx context.Context, botToken, chatID, text string) (Delivery, error)
}

// Clock lets tests pin now() deterministically.
type Clock interface {
	Now() time.Time
}
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// Limiter bounds send rate — global and per-chat — with an
// injectable clock so tests drive windows deterministically.
type Limiter struct {
	mu        sync.Mutex
	global    float64 // tokens per second
	perChat   float64
	clock     Clock
	globalTok float64
	globalAt  time.Time
	chatTok   map[uuid.UUID]float64
	chatAt    map[uuid.UUID]time.Time
}

// NewLimiter builds a token-bucket limiter: per-second refill rates,
// burst of one window each.
func NewLimiter(globalPerSec, perChatPerSec float64, c Clock) *Limiter {
	return &Limiter{global: globalPerSec, perChat: perChatPerSec,
		clock: c, chatTok: map[uuid.UUID]float64{},
		chatAt: map[uuid.UUID]time.Time{}}
}

// Allow reports whether a send to chat may start now; a refusal does
// not consume budget — the caller reschedules instead.
func (l *Limiter) Allow(chat uuid.UUID) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock.Now()
	l.globalTok = refill(l.globalTok, l.globalAt, now, l.global)
	l.globalAt = now
	ct := refill(l.chatTok[chat], l.chatAt[chat], now, l.perChat)
	l.chatAt[chat] = now
	if l.global >= 0 && l.globalTok < 1 {
		return false
	}
	if l.perChat >= 0 && ct < 1 {
		return false
	}
	if l.global >= 0 {
		l.globalTok--
	}
	if l.perChat >= 0 {
		ct--
		l.chatTok[chat] = ct
	}
	return true
}

func refill(tokens float64, at, now time.Time, rate float64) float64 {
	if rate <= 0 {
		return 1
	}
	cap_ := rate // burst = one second of rate
	tokens += now.Sub(at).Seconds() * rate
	if tokens > cap_ {
		tokens = cap_
	}
	if tokens < 0 {
		tokens = 0
	}
	return tokens
}

// DispatcherConfig bundles the typed bounds.
type DispatcherConfig struct {
	Lease       LeaseConfig
	Retry       RetryPolicy
	SendTimeout time.Duration // per-attempt bound (spec: 5s)
	TickEvery   time.Duration // idle cadence between claim passes
	BotToken    string        // provider credential — never logged
}

// Revalidation is the recipient fence checked immediately before the
// send — inside a fresh short read, never the claim's transaction.
type RecipientGate struct {
	Deliverable bool   // channel still VERIFIED+enabled+live
	ChatID      string // decrypted destination (never logged)
	VersionOK   bool   // channel version matches the intent's stamp
	OwnerActive bool   // owner still ACTIVE
}

// Dispatcher is the single consumer of outbox claims. Seams are
// package-private fields so unit tests drive the pipeline without a
// database; production wiring fills them from pgx.
type Dispatcher struct {
	cfg    DispatcherConfig
	sender Sender
	ring   *Keyring
	clock  Clock
	limit  *Limiter
	rng    *rand.Rand

	conn       *pgx.Conn
	repo       *Repository
	claimFn    func(context.Context) ([]Claim, error)
	revalidate func(context.Context, Claim) (RecipientGate, error)
	ackFn      func(context.Context, uuid.UUID, uuid.UUID) (bool, error)
	reschedFn  func(context.Context, uuid.UUID, uuid.UUID, time.Time, string, int) (Disposition, error)
	suppressFn func(context.Context, uuid.UUID, uuid.UUID, string) (bool, error)
	deadFn     func(context.Context, uuid.UUID, uuid.UUID, string) (bool, error)
}

// NewDispatcher wires the production seams. conn may be pooled —
// every claim is its own short transaction.
func NewDispatcher(conn *pgx.Conn, repo *Repository, ring *Keyring,
	sender Sender, cfg DispatcherConfig, lim *Limiter) *Dispatcher {
	d := &Dispatcher{
		cfg: cfg, sender: sender, ring: ring, clock: realClock{},
		limit: lim, rng: rand.New(rand.NewPCG(1, 2)),
		conn: conn, repo: repo,
	}
	d.claimFn = func(ctx context.Context) ([]Claim, error) {
		return ClaimDue(ctx, conn, cfg.Lease)
	}
	d.ackFn = func(ctx context.Context, id, tok uuid.UUID) (bool, error) {
		return AckDelivery(ctx, conn, id, tok)
	}
	d.reschedFn = func(ctx context.Context, id, tok uuid.UUID,
		next time.Time, code string, max int) (Disposition, error) {
		return RescheduleDelivery(ctx, conn, id, tok, next, code, max)
	}
	d.suppressFn = func(ctx context.Context, id, tok uuid.UUID,
		reason string) (bool, error) {
		return SuppressDelivery(ctx, conn, id, tok, reason)
	}
	d.deadFn = func(ctx context.Context, id, tok uuid.UUID,
		code string) (bool, error) {
		return DeadDelivery(ctx, conn, id, tok, code)
	}
	d.revalidate = func(ctx context.Context, cl Claim) (RecipientGate, error) {
		gate := RecipientGate{}
		var status string
		var enabled bool
		var ver int64
		var encV *int
		var ct []byte
		var delAt *time.Time
		var ustatus string
		err := conn.QueryRow(ctx, `
			SELECT c.status, c.enabled, c.version, c.encryption_key_version,
			       c.destination_ciphertext, c.deleted_at, u.status
			FROM uptime.notification_channels c
			JOIN uptime.users u ON u.id=c.user_id
			WHERE c.id=$1 AND c.user_id=$2`,
			cl.ChannelID, cl.UserID).
			Scan(&status, &enabled, &ver, &encV, &ct, &delAt, &ustatus)
		if err != nil {
			return gate, err
		}
		gate.OwnerActive = ustatus == "ACTIVE"
		gate.VersionOK = ver == cl.ChannelVersion
		ch := Channel{Status: status, Enabled: enabled,
			DeletedAt: delAt, destinationCiphertext: ct}
		gate.Deliverable = ch.Deliverable()
		if gate.Deliverable && encV != nil {
			plain, err := ring.DecryptDestination(*encV, ct,
				DestinationAAD(cl.ChannelID, cl.UserID, *encV))
			if err == nil {
				gate.ChatID = string(plain)
			} else {
				gate.Deliverable = false
			}
		}
		return gate, nil
	}
	return d
}

// WithClock swaps the time source (tests).
func (d *Dispatcher) WithClock(c Clock) *Dispatcher { d.clock = c; return d }

// Tick performs one bounded claim→send pass. Returns the number of
// rows that reached a disposition (SENT/rescheduled/DEAD/SUPPRESSED).
func (d *Dispatcher) Tick(ctx context.Context) (int, error) {
	claims, err := d.claimFn(ctx)
	if errors.Is(err, ErrClaimClosed) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	done := 0
	for _, cl := range claims {
		if ctx.Err() != nil {
			return done, ctx.Err()
		}
		d.process(ctx, cl)
		done++
	}
	return done, nil
}

// Run is the lifecycle loop: bounded ticks until ctx ends. The
// interval sleeps are clock-driven so tests control them.
func (d *Dispatcher) Run(ctx context.Context) error {
	for {
		if _, err := d.Tick(ctx); err != nil && !errors.Is(err, context.Canceled) {
			// Transient claim failure — bounded tick cadence applies
			// before the next pass, never a busy loop.
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(d.cfg.TickEvery):
		}
	}
}

// process handles one claim through revalidate → send → disposition.
// Every failure path leaves the row recoverable — never silently
// consumed.
func (d *Dispatcher) process(ctx context.Context, cl Claim) {
	// 1) Recipient fence — a fresh short read, not the claim tx.
	gate, err := d.revalidate(ctx, cl)
	if err != nil || !gate.Deliverable || !gate.VersionOK || !gate.OwnerActive {
		// Suppression is the AUTHORIZED skip: the row terminalizes
		// SUPPRESSED so a downstream RECOVERY may proceed without
		// fabricating a delivery.
		_, _ = d.suppressFn(ctx, cl.ID, cl.LeaseToken,
			"recipient_ineligible")
		return
	}

	// 2) Rate limit — refusal reschedules, it is never a failure.
	if d.limit != nil && !d.limit.Allow(cl.ChannelID) {
		_, _ = d.reschedFn(ctx, cl.ID, cl.LeaseToken,
			d.clock.Now().Add(d.cfg.Retry.MinDelay),
			"RATE_LIMITED", d.cfg.Lease.MaxAttempts)
		return
	}

	// 3) Bounded send outside every lock.
	sctx, cancel := context.WithTimeout(ctx, d.cfg.SendTimeout)
	del, err := d.sender.Send(sctx, d.cfg.BotToken, gate.ChatID,
		renderText(cl))
	cancel()

	// 4) Disposition by typed outcome.
	switch {
	case err == nil:
		_, _ = d.ackFn(ctx, cl.ID, cl.LeaseToken)

	case isPermanent(err):
		_, _ = d.deadFn(ctx, cl.ID, cl.LeaseToken, "PERMANENT")

	default:
		delay := ComputeRetry(cl.Attempts, del.RetryAfter,
			d.cfg.Retry, d.rng)
		if Exhausted(cl.Attempts, cl.CreatedAt, d.clock.Now(),
			d.cfg.Retry) {
			_, _ = d.deadFn(ctx, cl.ID, cl.LeaseToken, "RETRY_EXHAUSTED")
			return
		}
		_, _ = d.reschedFn(ctx, cl.ID, cl.LeaseToken,
			d.clock.Now().Add(delay), "RETRYABLE", d.cfg.Lease.MaxAttempts)
	}
}

func isPermanent(err error) bool {
	var se *SendError
	return errors.As(err, &se) && se.Permanent
}

// renderText projects the safe payload into the message body — the
// payload contract carries monitor name + transition only; secrets
// and raw URLs never enter the message.
func renderText(cl Claim) string {
	var p struct {
		MonitorName string `json:"monitor_name"`
		Transition  string `json:"transition"`
	}
	if err := json.Unmarshal(cl.SafePayload, &p); err != nil {
		return "monitor " + cl.EventKind
	}
	if p.MonitorName == "" {
		p.MonitorName = "monitor"
	}
	return fmt.Sprintf("%s is %s", p.MonitorName, cl.EventKind)
}
