package checker

import (
	"context"
	"io"
	"time"
)

// maxBodyBytes caps response-body reads. The body is never persisted
// and never reaches an Observation — it's drained only so the
// connection can close cleanly. Content-Length is never trusted for
// allocation.
const maxBodyBytes = 64 << 10 // 64 KiB

// Checker composes resolver + pinned transport into one bounded
// observation pass. Zero retries — a check attempts once and reports.
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

// Check performs one bounded observation:
//
//  1. derive the attempt deadline — the target's configured timeout,
//     which can only SHRINK inside an earlier parent deadline;
//  2. validate the destination (parse → resolve → per-answer policy);
//  3. issue a single GET through the pinned transport;
//  4. drain at most maxBodyBytes so the socket closes cleanly;
//  5. classify into an Observation — target evidence or a
//     collector-side exclusion, never both.
//
// Latency is monotonic-derived elapsed time of the attempt; canceled
// work measures nothing and produces no success evidence.
func (c *Checker) Check(ctx context.Context, t Target) (Observation, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(t.TimeoutSeconds)*time.Second)
	defer cancel()
	start := time.Now()
	build := func(outcome Outcome, status *int) (Observation, error) {
		ms := time.Since(start).Milliseconds()
		return NewObservation(t, outcome, status, &ms, time.Now())
	}
	fail := func(err error) (Observation, error) {
		return build(ClassifyError(err), nil)
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
	resp, err := newClient(rt, c.dial).Do(req)
	if err != nil {
		return fail(err)
	}
	defer resp.Body.Close()
	// Bounded drain — allocation is capped by the limit reader, not
	// by Content-Length; the rest of the stream is discarded unread
	// (keep-alives are off, so closing is already correct).
	if _, err := ReadBoundedResponse(resp.Body, maxBodyBytes); err != nil {
		return fail(err)
	}
	st := resp.StatusCode
	if IsExpectedStatus(t, st) {
		return build(OutcomeSuccess, &st)
	}
	return build(OutcomeUnexpectedStatus, &st)
}

// ReadBoundedResponse reads at most max bytes from r. It never
// over-allocates from headers and returns the capped payload — the
// caller decides whether a truncated body matters (for health
// observation it does not).
func ReadBoundedResponse(r io.Reader, max int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, max))
}
