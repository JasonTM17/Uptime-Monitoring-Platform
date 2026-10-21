package checker

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// httpStub serves plain HTTP on loopback through a real httptest
// server — the pinned dial records the requested address but connects
// to the stub. closed counts server-side connection closes.
type httpStub struct {
	url    string
	seen   *[]string
	closed *int32
	mu     *sync.Mutex
}

func startHTTPStub(t *testing.T, handler http.HandlerFunc) *httpStub {
	var seen []string
	var closed int32
	var mu sync.Mutex
	srv := httptest.NewUnstartedServer(handler)
	srv.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateClosed {
			mu.Lock()
			closed++
			mu.Unlock()
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return &httpStub{url: srv.URL, seen: &seen, closed: &closed, mu: &mu}
}

func (h *httpStub) dialer() DialFunc {
	host := strings.TrimPrefix(h.url, "http://")
	return func(_ context.Context, _, address string) (net.Conn, error) {
		h.mu.Lock()
		*h.seen = append(*h.seen, address)
		h.mu.Unlock()
		d := &net.Dialer{Timeout: 2 * time.Second}
		return d.DialContext(context.Background(), "tcp", host)
	}
}

func (h *httpStub) closedConns() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return int(*h.closed)
}

func checkerFor(t *testing.T, stub *httpStub) *Checker {
	res := &fakeResolver{answers: []net.IP{net.ParseIP("93.184.216.34")}}
	return newChecker(res, stub.dialer())
}

func targetFor(url string, timeout int) Target {
	return Target{
		MonitorID:      uuid.MustParse("00000000-0000-0000-0000-000000000042"),
		URL:            url,
		TimeoutSeconds: timeout,
	}
}

func TestHTTPStatusPolicy(t *testing.T) {
	cases := []struct {
		name       string
		serverCode int
		expected   *int
		want       Outcome
	}{
		{"ok-200", 200, nil, OutcomeSuccess},
		{"ok-204", 204, nil, OutcomeSuccess},
		{"ok-299", 299, nil, OutcomeSuccess},
		{"unexpected-500", 500, nil, OutcomeUnexpectedStatus},
		{"redirect-not-followed", 302, nil, OutcomeUnexpectedStatus},
		{"custom-expected-match", 418, intPtr(418), OutcomeSuccess},
		{"custom-expected-miss", 200, intPtr(418), OutcomeUnexpectedStatus},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := startHTTPStub(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.serverCode)
				w.Write([]byte("body"))
			})
			c := checkerFor(t, stub)
			tg := targetFor("http://check.example/health", 5)
			tg.ExpectedStatus = tc.expected
			o := c.Check(context.Background(), tg)
			if o.Outcome != tc.want {
				t.Fatalf("outcome = %d, want %d", o.Outcome, tc.want)
			}
			if o.Status == nil || *o.Status != tc.serverCode {
				t.Fatalf("status = %v, want %d", o.Status, tc.serverCode)
			}
			if o.LatencyMs == nil {
				t.Fatal("status outcome must carry latency")
			}
		})
	}
}

func TestBoundedBody(t *testing.T) {
	t.Run("huge-body-capped", func(t *testing.T) {
		stub := startHTTPStub(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			w.Write(make([]byte, 1<<20)) // 1 MiB
		})
		c := checkerFor(t, stub)
		o := c.Check(context.Background(), targetFor("http://check.example/", 5))
		if o.Outcome != OutcomeSuccess {
			t.Fatalf("oversized body must not fail a valid status, got %d", o.Outcome)
		}
	})
	t.Run("chunked-body", func(t *testing.T) {
		stub := startHTTPStub(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Transfer-Encoding", "chunked")
			fl, _ := w.(http.Flusher)
			w.WriteHeader(200)
			for i := 0; i < 8; i++ {
				w.Write([]byte(strings.Repeat("x", 4096)))
				fl.Flush()
			}
		})
		c := checkerFor(t, stub)
		o := c.Check(context.Background(), targetFor("http://check.example/", 5))
		if o.Outcome != OutcomeSuccess {
			t.Fatalf("got %d", o.Outcome)
		}
	})
	t.Run("read-cap-direct", func(t *testing.T) {
		got, err := ReadBoundedResponse(strings.NewReader(strings.Repeat("y", 1<<20)), maxBodyBytes)
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(got)) != maxBodyBytes {
			t.Fatalf("read %d, want cap %d", len(got), maxBodyBytes)
		}
	})
}

func TestResponseCleanup(t *testing.T) {
	stub := startHTTPStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte("oops"))
	})
	c := checkerFor(t, stub)
	// Non-2xx responses must still close the body — cleanup is
	// status-independent.
	for i := 0; i < 3; i++ {
		o := c.Check(context.Background(), targetFor("http://check.example/", 5))
		if o.Outcome != OutcomeUnexpectedStatus {
			t.Fatalf("got %d", o.Outcome)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for stub.closedConns() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if stub.closedConns() < 3 {
		t.Fatalf("only %d conns closed after 3 checks", stub.closedConns())
	}
}

func TestParentCancellation(t *testing.T) {
	release := make(chan struct{})
	stub := startHTTPStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fl, _ := w.(http.Flusher)
		fl.Flush()
		<-release // hold the body open until released
	})
	defer close(release)
	c := checkerFor(t, stub)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan Observation, 1)
	go func() {
		o := c.Check(ctx, targetFor("http://check.example/", 10))
		done <- o
	}()
	time.Sleep(100 * time.Millisecond) // let the request reach the hold
	cancel()
	select {
	case o := <-done:
		if o.Outcome != OutcomeCanceled {
			t.Fatalf("parent cancel must produce CANCELED, got %d", o.Outcome)
		}
		if o.Status != nil {
			t.Fatal("canceled observation must not carry a status")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Check did not return after parent cancel")
	}
}

func TestDeadlineExceeded(t *testing.T) {
	stub := startHTTPStub(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second) // slower than any test timeout
		w.WriteHeader(200)
	})
	c := checkerFor(t, stub)
	tg := targetFor("http://check.example/", 1) // 1s budget
	o := c.Check(context.Background(), tg)
	if o.Outcome != OutcomeTimeout {
		t.Fatalf("slow target must produce TIMEOUT, got %d", o.Outcome)
	}
}

func TestPolicyBlockedObservation(t *testing.T) {
	var dials int
	c := newChecker(&fakeResolver{}, func(_ context.Context, _, _ string) (net.Conn, error) {
		dials++
		return nil, context.DeadlineExceeded
	})
	o := c.Check(context.Background(), targetFor("http://127.0.0.1/", 5))
	if o.Outcome != OutcomePolicyBlocked {
		t.Fatalf("got %d", o.Outcome)
	}
	if o.Outcome.IsEligible() {
		t.Fatal("policy block must not be target evidence")
	}
	if dials != 0 {
		t.Fatalf("policy-blocked check still dialed %d times", dials)
	}
}
func intPtr(v int) *int { return &v }

// Headers beyond the cap are a collector bound — the check fails
// closed as an excluded outcome, never a fake status or a hang.
func TestHeaderCap(t *testing.T) {
	stub := startHTTPStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Pad", strings.Repeat("h", maxHeaderBytes+4096))
		w.WriteHeader(200)
	})
	c := checkerFor(t, stub)
	o := c.Check(context.Background(), targetFor("http://check.example/", 5))
	if o.Outcome != OutcomeInternalError {
		t.Fatalf("oversized headers = %d, want INTERNAL_ERROR exclusion", o.Outcome)
	}
}

// Out-of-contract timeouts are collector defects — INTERNAL_ERROR,
// never eligible TIMEOUT evidence fabricated from bad config.
func TestTimeoutBound(t *testing.T) {
	stub := startHTTPStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	c := checkerFor(t, stub)
	for _, sec := range []int{0, -1, 11, 1000} {
		o := c.Check(context.Background(), targetFor("http://check.example/", sec))
		if o.Outcome != OutcomeInternalError {
			t.Fatalf("timeout %ds = %d, want INTERNAL_ERROR", sec, o.Outcome)
		}
	}
}
