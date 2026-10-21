package checker

import (
	"context"
	"errors"
	"net"
	"net/http"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Fault injection at each pipeline phase must map to the right enum —
// an internal collector fault must never masquerade as target DOWN.
func TestDeadlineClassification(t *testing.T) {
	slowHeaders := startHTTPStub(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1500 * time.Millisecond) // exceeds the 1s budget
		w.WriteHeader(200)
	})
	slowBody := startHTTPStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fl, _ := w.(http.Flusher)
		fl.Flush()
		time.Sleep(1500 * time.Millisecond)
		w.Write([]byte("late"))
	})
	okStub := startHTTPStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})

	pubResolver := &fakeResolver{answers: []net.IP{net.ParseIP("93.184.216.34")}}
	pubDial := okStub.dialer()

	cases := []struct {
		name    string
		res     Resolver
		dial    DialFunc
		timeout int
		want    Outcome
	}{
		{
			name: "dns-failure",
			res:  &fakeResolver{err: &net.DNSError{Err: "no such host", IsNotFound: true}},
			dial: pubDial, timeout: 2, want: OutcomeDNSError,
		},
		{
			name: "connect-refused",
			res:  pubResolver,
			dial: func(_ context.Context, _, _ string) (net.Conn, error) {
				return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
			},
			timeout: 2, want: OutcomeConnectError,
		},
		{
			name: "dial-timeout",
			res:  pubResolver,
			dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			},
			timeout: 1, want: OutcomeTimeout,
		},
		{
			name:    "slow-headers",
			res:     pubResolver,
			dial:    slowHeaders.dialer(),
			timeout: 1, want: OutcomeTimeout,
		},
		{
			name:    "slow-body-after-headers",
			res:     pubResolver,
			dial:    slowBody.dialer(),
			timeout: 1, want: OutcomeTimeout,
		},
		{
			name: "unknown-internal",
			res:  pubResolver,
			dial: func(_ context.Context, _, _ string) (net.Conn, error) {
				return nil, errors.New("socket exhausted")
			},
			timeout: 2, want: OutcomeInternalError,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newChecker(tc.res, tc.dial)
			o, err := c.Check(context.Background(), targetFor("http://check.example/", tc.timeout))
			if err != nil {
				t.Fatal(err)
			}
			if o.Outcome != tc.want {
				t.Fatalf("phase fault classified %d, want %d", o.Outcome, tc.want)
			}
			if o.Outcome == OutcomeInternalError && o.Outcome.IsEligible() {
				t.Fatal("internal fault must not count as target DOWN")
			}
		})
	}
}

// Cancellation after response headers — mid-body — still produces
// the CANCELED exclusion, and the in-flight body is abandoned.
func TestCancelAfterHeaders(t *testing.T) {
	release := make(chan struct{})
	stub := startHTTPStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fl, _ := w.(http.Flusher)
		fl.Flush() // headers delivered; body pending
		<-release
	})
	defer close(release)
	c := checkerFor(t, stub)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan Observation, 1)
	go func() {
		o, _ := c.Check(ctx, targetFor("http://check.example/", 30))
		done <- o
	}()
	time.Sleep(120 * time.Millisecond) // headers arrive, body stalls
	cancel()
	select {
	case o := <-done:
		if o.Outcome != OutcomeCanceled {
			t.Fatalf("mid-body cancel = %d, want CANCELED", o.Outcome)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Check did not return after mid-body cancel")
	}
}

// Concurrent checks through one Checker must stay isolated — and the
// race detector must stay silent.
func TestConcurrentChecks(t *testing.T) {
	stub := startHTTPStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})
	c := checkerFor(t, stub)
	var wg sync.WaitGroup
	outcomes := make([]Outcome, 16)
	for i := range outcomes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			o, err := c.Check(context.Background(), targetFor("http://check.example/", 5))
			if err != nil {
				outcomes[i] = OutcomeInternalError
				return
			}
			outcomes[i] = o.Outcome
		}(i)
	}
	wg.Wait()
	for i, oc := range outcomes {
		if oc != OutcomeSuccess {
			t.Fatalf("check %d outcome = %d", i, oc)
		}
	}
}

// A bounded goroutine-growth check: after N checks the runtime should
// settle back near baseline. Tolerance is generous — GC and httptest
// keepers are implementation details, not a 1-goroutine guarantee.
func TestGoroutineBounds(t *testing.T) {
	stub := startHTTPStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	c := checkerFor(t, stub)
	// Warm up once so steady-state allocations don't skew the count.
	_, _ = c.Check(context.Background(), targetFor("http://check.example/", 2))
	base := runtime.NumGoroutine()
	for i := 0; i < 20; i++ {
		_, _ = c.Check(context.Background(), targetFor("http://check.example/", 2))
	}
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > base+8 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > base+8 {
		t.Fatalf("goroutines grew %d -> %d across 20 checks", base, got)
	}
}
