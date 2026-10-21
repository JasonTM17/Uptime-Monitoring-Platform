package checker

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// maxBodyBytes caps response-body reads. The body is never persisted
// and never reaches an Observation — it's drained only so the
// connection can close cleanly. Content-Length is never trusted for
// allocation.
const maxBodyBytes = 64 << 10 // 64 KiB

// Timeout bounds mirror the C19 create contract — a Target that
// arrives out-of-range is a collector defect, never target evidence.
const (
	minTimeoutSeconds = 1
	maxTimeoutSeconds = 10
)

// Checker composes resolver + pinned transport into one bounded
// observation pass. Zero retries — a check attempts once and reports.
// It is safe for concurrent use: each Check builds its own immutable
// resolution and transport.
type Checker struct {
	resolver Resolver
	dial     DialFunc
}

// NewChecker is the production constructor: system DNS + real sockets.
func NewChecker(res Resolver) *Checker {
	return &Checker{resolver: res, dial: defaultDial}
}

func newChecker(res Resolver, dial DialFunc) *Checker {
	return &Checker{resolver: res, dial: dial}
}

// Check performs one bounded observation and returns ONLY the
// observation — there is no error return to drop. Any collector-side
// fault becomes OutcomeInternalError (excluded evidence), so a caller
// can never fabricate success by ignoring a second return value.
//
//  1. validate the target contract (timeout 1..10 — else INTERNAL);
//  2. derive the attempt deadline — the target's configured timeout,
//     which can only SHRINK inside an earlier parent deadline. The
//     caller must not wrap a shorter deadline itself: an engine-side
//     shorter timeout would produce eligible TIMEOUT evidence for a
//     collector constraint;
//  3. validate the destination (parse → resolve → per-answer policy);
//  4. issue a single GET through the pinned transport;
//  5. drain at most maxBodyBytes so the socket closes cleanly;
//  6. classify into an Observation — target evidence or a
//     collector-side exclusion, never both.
func (c *Checker) Check(ctx context.Context, t Target) Observation {
	build := func(outcome Outcome, status *int, latency *int64) Observation {
		o, err := NewObservation(t, outcome, status, latency, time.Now())
		if err != nil {
			// Constructor invariants can't fail on our own calls —
			// if they ever do, fail safe as an excluded internal
			// outcome rather than returning a zero-value SUCCESS.
			o, _ = NewObservation(t, OutcomeInternalError, nil, nil, time.Now())
		}
		return o
	}
	if c.resolver == nil || c.dial == nil {
		return build(OutcomeInternalError, nil, nil)
	}
	if t.TimeoutSeconds < minTimeoutSeconds || t.TimeoutSeconds > maxTimeoutSeconds {
		return build(OutcomeInternalError, nil, nil)
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(t.TimeoutSeconds)*time.Second)
	defer cancel()
	start := time.Now()
	evidence := func(outcome Outcome, status *int) Observation {
		ms := time.Since(start).Milliseconds()
		return build(outcome, status, &ms)
	}
	fail := func(err error) Observation {
		return evidence(ClassifyError(err), nil)
	}

	pt, err := ParseTarget(t.URL)
	if err != nil {
		return fail(err)
	}
	rt, err := ResolveValidated(ctx, c.resolver, pt)
	if err != nil {
		return fail(err)
	}
	req, err := BuildRequest(ctx, rt, t.URL)
	if err != nil {
		return fail(err)
	}
	tr := newSafeTransport(rt, c.dial)
	defer tr.CloseIdleConnections()
	resp, err := httpClientFor(tr).Do(req)
	if err != nil {
		return fail(err)
	}
	defer resp.Body.Close()
	// Bounded drain — allocation is capped by the limit reader, not
	// by Content-Length; the rest of the stream is discarded unread
	// (keep-alives are off, so closing is already correct).
	if _, err := ReadBoundedResponse(resp.Body, maxBodyBytes); err != nil {
		return fail(fmt.Errorf("body read: %w", err))
	}
	st := resp.StatusCode
	if IsExpectedStatus(t, st) {
		return evidence(OutcomeSuccess, &st)
	}
	return evidence(OutcomeUnexpectedStatus, &st)
}

// httpClientFor composes the pinned transport + redirect refusal.
// Redirects are never followed: a 3xx is the target's answer
// (OutcomeUnexpectedStatus), never a second unvalidated dial.
func httpClientFor(tr *http.Transport) *http.Client {
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ReadBoundedResponse reads at most max bytes from r. It never
// over-allocates from headers and returns the capped payload — the
// caller decides whether a truncated body matters (for health
// observation it does not).
func ReadBoundedResponse(r io.Reader, max int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, max))
}
