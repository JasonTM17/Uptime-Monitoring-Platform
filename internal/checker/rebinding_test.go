package checker

import (
	"context"
	"net"
	"net/http"
	"sync"
	"testing"
)

// rebindResolver answers public on the first lookup and private on
// every later one — the classic DNS-rebinding schedule.
type rebindResolver struct {
	mu    sync.Mutex
	calls int
}

func (r *rebindResolver) LookupIP(_ context.Context, _ string) ([]net.IP, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.calls == 1 {
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}
	return []net.IP{net.ParseIP("169.254.169.254")}, nil
}

// The pinned transport must never ask DNS a second time: after the
// validated resolution, a later (rebound) private answer is simply
// unreachable — there is no second lookup to lie to.
func TestDNSRebinding(t *testing.T) {
	res := &rebindResolver{}
	var seen []string
	var mu sync.Mutex
	dial := func(_ context.Context, _, address string) (net.Conn, error) {
		mu.Lock()
		seen = append(seen, address)
		mu.Unlock()
		return nil, context.DeadlineExceeded // dial result irrelevant
	}
	c := newChecker(res, dial)
	// Every check performs its own resolution — rebinding is caught
	// two ways: run 1 dials the validated public set; runs 2+ get
	// the rebound private answer and are policy-blocked outright.
	for i := 0; i < 3; i++ {
		o := c.Check(context.Background(), targetFor("http://rebind.example/", 3))
		if i == 0 && o.Outcome != OutcomeTimeout {
			t.Fatalf("run %d: outcome = %d", i, o.Outcome)
		}
		if i > 0 && o.Outcome != OutcomePolicyBlocked {
			t.Fatalf("run %d: rebound private answer must be blocked, got %d", i, o.Outcome)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if res.calls != 3 {
		t.Fatalf("expected exactly one lookup per check, got %d", res.calls)
	}
	for _, a := range seen {
		if a != "93.184.216.34:80" {
			t.Fatalf("dial escaped the approved set to %q — rebinding reached the wire", a)
		}
	}
}

// Private answers produce ZERO dials — a denial that never reaches
// the dialer, not a dial that fails.
func TestNoPrivateDial(t *testing.T) {
	res := &fakeResolver{answers: []net.IP{net.ParseIP("10.0.0.5"), net.ParseIP("169.254.169.254")}}
	var seen []string
	var mu sync.Mutex
	dial := func(_ context.Context, _, address string) (net.Conn, error) {
		mu.Lock()
		seen = append(seen, address)
		mu.Unlock()
		return nil, context.DeadlineExceeded
	}
	c := newChecker(res, dial)
	o := c.Check(context.Background(), targetFor("http://internal.example/", 3))
	if o.Outcome != OutcomePolicyBlocked {
		t.Fatalf("private answer must be policy-blocked, got %d", o.Outcome)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 0 {
		t.Fatalf("private destination reached the dialer: %v", seen)
	}
}

// Positive control: a public answer produces a REAL request — the
// zero-dial assertions above can't be passed by a deny-everything
// fake that dials nothing.
func TestLegitimatePublicFixture(t *testing.T) {
	stub := startHTTPStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})
	c := checkerFor(t, stub)
	o := c.Check(context.Background(), targetFor("http://legit.example/", 3))
	if o.Outcome != OutcomeSuccess {
		t.Fatalf("public target must be checkable, got %d", o.Outcome)
	}
	stub.mu.Lock()
	dials := *stub.seen
	stub.mu.Unlock()
	if len(dials) != 1 || dials[0] != "93.184.216.34:80" {
		t.Fatalf("expected exactly one pinned dial, got %v", dials)
	}
}

// Negative oracle experiment: a DELIBERATELY unsafe composition —
// validate once, then dial the hostname (which re-resolves and hits
// the rebound private answer). If this experiment did NOT reach the
// private address, the zero-dial assertions above would be vacuous.
func TestUnsafeSubstituteWouldFail(t *testing.T) {
	res := &rebindResolver{}
	var dialed []string
	var mu sync.Mutex
	// Simulates validate-then-default-dial: every "connection"
	// re-asks the resolver, then records where it would connect.
	unsafeDial := func(ctx context.Context, _, address string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(address)
		ips, _ := res.LookupIP(ctx, host)
		for _, ip := range ips {
			mu.Lock()
			dialed = append(dialed, ip.String())
			mu.Unlock()
		}
		return nil, context.DeadlineExceeded
	}
	_, _ = unsafeDial(context.Background(), "tcp", "rebind.example:80")
	_, _ = unsafeDial(context.Background(), "tcp", "rebind.example:80")
	mu.Lock()
	defer mu.Unlock()
	foundPrivate := false
	for _, a := range dialed {
		if a == "169.254.169.254" {
			foundPrivate = true
		}
	}
	if !foundPrivate {
		t.Fatal("unsafe substitute failed to reach the private answer — the zero-dial oracle is vacuous")
	}
}

// A canceled parent produces zero dials — cancellation before the
// dial is not a connection attempt.
func TestCancelBeforeDial(t *testing.T) {
	res := &fakeResolver{answers: []net.IP{net.ParseIP("93.184.216.34")}}
	var seen []string
	var mu sync.Mutex
	dial := func(_ context.Context, _, address string) (net.Conn, error) {
		mu.Lock()
		seen = append(seen, address)
		mu.Unlock()
		return nil, context.DeadlineExceeded
	}
	c := newChecker(res, dial)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	o := c.Check(ctx, targetFor("http://x.example/", 3))
	if o.Outcome != OutcomeCanceled {
		t.Fatalf("got %d", o.Outcome)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 0 {
		t.Fatalf("canceled check reached the dialer: %v", seen)
	}
}
