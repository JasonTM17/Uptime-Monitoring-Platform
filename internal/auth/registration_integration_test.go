//go:build integration

package auth_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/auth"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/config"
)

const validPW = "a very long password!"

// TestConcurrentRegistration proves the canonical unique constraint —
// not application-side checking — serializes a same-email race into
// exactly one account.
func TestConcurrentRegistration(t *testing.T) {
	repo := auth.NewRepository(testPool(t), 10*time.Second)
	hasher := auth.NewHasher(config.AuthConfig{
		ArgonMemoryKiB: 19 * 1024, ArgonTime: 2, ArgonParallelism: 1,
		ArgonSaltLen: 16, ArgonKeyLen: 32, HashWorkers: 2,
	})
	svc := auth.NewService(repo, hasher, intCfg(), 10)
	ctx := context.Background()

	email := unqEmail("race")

	const racers = 6
	errs := make([]error, racers)
	var okCount int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			// Same canonical email, different raw casings.
			raw := []string{strings.ToUpper(email), email,
				strings.ToUpper(email), " " + email + " ",
				strings.ToUpper(email[:1]) + email[1:], email}[i]
			var err error
			for try := 0; try < 40; try++ {
				_, err = svc.Register(ctx, auth.RegisterInput{
					Email: raw, Password: validPW})
				// The bounded hash gate is backpressure, not a verdict:
				// retry past transient saturation (bounded).
				if !errors.Is(err, auth.ErrHashBusy) {
					break
				}
				time.Sleep(30 * time.Millisecond)
			}
			errs[i] = err
			if err == nil {
				okCount++
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if okCount != 1 {
		t.Fatalf("expected exactly 1 success, got %d (errs=%v)", okCount, errs)
	}
	for i, err := range errs {
		if err != nil && !errors.Is(err, auth.ErrEmailTaken) {
			t.Fatalf("racer %d: expected nil or ErrEmailTaken, got %v", i, err)
		}
	}
	// Exactly one canonical row persisted.
	conn := connect(t)
	var n int
	if err := conn.QueryRow(ctx,
		"SELECT count(*) FROM uptime.users WHERE email=$1", email).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 canonical row, got %d", n)
	}
	_ = conn.Close(ctx)
}

// intCfg returns service config for integration tests.
func intCfg() config.AuthConfig {
	return config.AuthConfig{
		SessionAbsoluteExpiry:      7 * 24 * time.Hour,
		SessionIdleExpiry:          24 * time.Hour,
		LoginIPAttemptsPerMin:      5,
		LoginAccountAttemptsPer15M: 5,
		// All requests share the httptest RemoteAddr; identity semantics
		// under test here are not the budget itself (unit-tested).
		RegisterIPAttemptsPerMin: 1000,
		LimiterMaxKeys:           1000,
	}
}
