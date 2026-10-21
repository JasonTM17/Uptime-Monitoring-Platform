package checker

import (
	"context"
	"net/http"
	"sync"
	"testing"
)

// A 30x pointing ANYWHERE — private, loopback, another host, another
// scheme — must be the target's answer, never a second dial. The
// dial recorder is the oracle: exactly one pinned dial per check.
func TestRedirectNeverFollowed(t *testing.T) {
	locations := map[string]string{
		"301-private":  "http://169.254.169.254/latest/meta-data",
		"302-loopback": "http://127.0.0.1:8080/admin",
		"303-other":    "http://evil.example/x",
		"307-scheme":   "ftp://internal.example/file",
		"308-relative": "/elsewhere",
	}
	for name, loc := range locations {
		t.Run(name, func(t *testing.T) {
			stub := startHTTPStub(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", loc)
				w.WriteHeader(302)
			})
			c := checkerFor(t, stub)
			o, err := c.Check(context.Background(), targetFor("http://check.example/", 3))
			if err != nil {
				t.Fatal(err)
			}
			if o.Outcome != OutcomeUnexpectedStatus {
				t.Fatalf("redirect must evaluate as target status, got %d", o.Outcome)
			}
			if o.Status == nil || *o.Status != 302 {
				t.Fatalf("status = %v, want 302", o.Status)
			}
			stub.mu.Lock()
			dials := *stub.seen
			stub.mu.Unlock()
			if len(dials) != 1 || dials[0] != "93.184.216.34:80" {
				t.Fatalf("redirect produced an unapproved second dial: %v", dials)
			}
		})
	}
}

// Redirected requests in-flight during a cancellation must still
// leave zero extra dials.
func TestRedirectUnderCancelNoExtraDial(t *testing.T) {
	var calls int
	var mu sync.Mutex
	stub := startHTTPStub(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.Header().Set("Location", "http://10.0.0.9/")
		w.WriteHeader(301)
	})
	c := checkerFor(t, stub)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan Observation, 1)
	go func() {
		o, _ := c.Check(ctx, targetFor("http://check.example/", 3))
		done <- o
	}()
	o := <-done
	cancel()
	if o.Outcome != OutcomeUnexpectedStatus {
		t.Fatalf("got %d", o.Outcome)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("server saw %d requests — a redirect was followed", calls)
	}
}
