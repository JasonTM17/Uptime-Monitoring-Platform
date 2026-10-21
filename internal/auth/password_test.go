package auth

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/config"
)

// testHasher uses the OWASP floor (19MiB/t2/p1) so tests stay fast;
// production params get one dedicated case.
func testCfg() config.AuthConfig {
	return config.AuthConfig{
		ArgonMemoryKiB:   19 * 1024,
		ArgonTime:        2,
		ArgonParallelism: 1,
		ArgonSaltLen:     16,
		ArgonKeyLen:      32,
		HashWorkers:      2,
		// Session/limiter fields needed by Service.
		SessionAbsoluteExpiry:      7 * 24 * time.Hour,
		SessionIdleExpiry:          24 * time.Hour,
		LoginIPAttemptsPerMin:      5,
		LoginAccountAttemptsPer15M: 5,
		RegisterIPAttemptsPerMin:   5,
		LimiterMaxKeys:             1000,
	}
}

func TestPassword(t *testing.T) {
	h := NewHasher(testCfg())
	ctx := context.Background()

	t.Run("hash and verify round trip", func(t *testing.T) {
		phc, err := h.HashPassword(ctx, "correct horse battery staple")
		if err != nil {
			t.Fatalf("hash: %v", err)
		}
		if !strings.HasPrefix(phc, "$argon2id$v=") {
			t.Fatalf("not PHC argon2id: %q", phc)
		}
		ok, err := h.VerifyPassword(ctx, "correct horse battery staple", phc)
		if err != nil || !ok {
			t.Fatalf("verify: %v ok=%v", err, ok)
		}
	})

	t.Run("same password hashes differently (random salt)", func(t *testing.T) {
		a, _ := h.HashPassword(ctx, "pw")
		b, _ := h.HashPassword(ctx, "pw")
		if a == b {
			t.Fatal("identical PHC for two hashes — salt is not random")
		}
	})

	t.Run("wrong password fails", func(t *testing.T) {
		phc, _ := h.HashPassword(ctx, "right")
		ok, err := h.VerifyPassword(ctx, "wrong", phc)
		if err != nil || ok {
			t.Fatalf("expected verify failure, err=%v ok=%v", err, ok)
		}
	})

	t.Run("password is never trimmed", func(t *testing.T) {
		phc, err := h.HashPassword(ctx, " spaced ")
		if err != nil {
			t.Fatalf("hash: %v", err)
		}
		ok, _ := h.VerifyPassword(ctx, "spaced", phc)
		if ok {
			t.Fatal("trimmed password verified — input must not be trimmed")
		}
	})

	t.Run("unicode and long password", func(t *testing.T) {
		pw := "mật-khẩu-🔐-" + strings.Repeat("x", 100)
		phc, err := h.HashPassword(ctx, pw)
		if err != nil {
			t.Fatalf("hash: %v", err)
		}
		ok, _ := h.VerifyPassword(ctx, pw, phc)
		if !ok {
			t.Fatal("unicode password failed to verify")
		}
	})

	t.Run("overlength input bounded before KDF", func(t *testing.T) {
		if _, err := h.HashPassword(ctx, strings.Repeat("a", maxPasswordBytes+1)); !errors.Is(err, ErrPasswordTooLong) {
			t.Fatalf("expected ErrPasswordTooLong, got %v", err)
		}
	})

	t.Run("malformed PHC rejected", func(t *testing.T) {
		cases := []string{
			"", "argon2id", "$argon2i$v=19$m=65536,t=3,p=1$AAAA$BBBB",
			"$argon2id$v=18$m=65536,t=3,p=1$AAAA$BBBB",
			"$argon2id$v=19$m=65536,t=3$AAAA$BBBB",
			"$argon2id$v=19$m=abc,t=3,p=1$AAAA$BBBB",
			"$argon2id$v=19$m=65536,t=3,p=1$!!!$BBBB",
			"$argon2id$v=19$m=65536,t=3,p=1$AAAA$!!!",
			"$argon2id$v=19$m=65536,t=3,p=1,x=1$AAAA$BBBB",
			// duplicate param is malformed, never last-wins:
			"$argon2id$v=19$m=8,t=3,p=1,m=999999999$AAAA$BBBB",
		}
		for i, c := range cases {
			if _, err := h.VerifyPassword(ctx, "pw", c); err == nil || errors.Is(err, ErrCostExceeded) {
				t.Fatalf("case %d: expected malformed-hash error, got %v", i, err)
			}
		}
	})

	t.Run("hostile cost in stored PHC is refused before allocation", func(t *testing.T) {
		// 4 GiB memory claim — must hit the ceiling, not the allocator.
		evil := "$argon2id$v=19$m=4194304,t=3,p=1$" +
			"QUJDREVGR0g=" + "$" + "QUJDREVGR0hJSktMTU5PUA=="
		if _, err := h.VerifyPassword(ctx, "pw", evil); !errors.Is(err, ErrCostExceeded) {
			t.Fatalf("expected ErrCostExceeded, got %v", err)
		}
	})

	t.Run("production params hash once", func(t *testing.T) {
		prod := NewHasher(config.AuthConfig{
			ArgonMemoryKiB: 64 * 1024, ArgonTime: 3, ArgonParallelism: 1,
			ArgonSaltLen: 16, ArgonKeyLen: 32, HashWorkers: 1,
		})
		phc, err := prod.HashPassword(ctx, "pw")
		if err != nil {
			t.Fatalf("prod hash: %v", err)
		}
		if !strings.Contains(phc, "m=65536,t=3,p=1") {
			t.Fatalf("unexpected prod PHC: %q", phc)
		}
	})
}

func TestHashGate(t *testing.T) {
	g := NewHashGate(2, 8) // workers + queue covers all 10 racers
	ctx := context.Background()

	t.Run("never exceeds worker bound", func(t *testing.T) {
		var inFlight int32
		var maxSeen int32
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := g.Acquire(ctx); err != nil {
					return
				}
				n := atomic.AddInt32(&inFlight, 1)
				for {
					m := atomic.LoadInt32(&maxSeen)
					if n <= m || atomic.CompareAndSwapInt32(&maxSeen, m, n) {
						break
					}
				}
				time.Sleep(5 * time.Millisecond)
				atomic.AddInt32(&inFlight, -1)
				g.Release()
			}()
		}
		wg.Wait()
		if maxSeen > 2 {
			t.Fatalf("concurrency exceeded bound: %d", maxSeen)
		}
	})

	t.Run("acquire honors cancellation and frees nothing", func(t *testing.T) {
		if err := g.Acquire(ctx); err != nil {
			t.Fatal(err)
		}
		if err := g.Acquire(ctx); err != nil {
			t.Fatal(err)
		}
		cctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()
		if err := g.Acquire(cctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected deadline, got %v", err)
		}
	})

	t.Run("bounded queue fails fast with ErrHashBusy", func(t *testing.T) {
		g2 := NewHashGate(1, 1) // 1 running + 1 waiting, 3rd refuses
		if err := g2.Acquire(ctx); err != nil {
			t.Fatal(err)
		}
		waiterErr := make(chan error, 1)
		go func() { waiterErr <- g2.Acquire(ctx) }()
		for len(g2.wait) == 0 { // deterministic: waiter holds the queue slot
			runtime.Gosched()
		}
		if err := g2.Acquire(ctx); !errors.Is(err, ErrHashBusy) {
			t.Fatalf("expected ErrHashBusy, got %v", err)
		}
		g2.Release()
		if err := <-waiterErr; err != nil {
			t.Fatalf("waiter did not acquire: %v", err)
		}
		g2.Release()
	})
}

func BenchmarkPassword(b *testing.B) {
	h := NewHasher(config.AuthConfig{
		ArgonMemoryKiB: 64 * 1024, ArgonTime: 3, ArgonParallelism: 1,
		ArgonSaltLen: 16, ArgonKeyLen: 32, HashWorkers: 2,
	})
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := h.HashPassword(ctx, "benchmark-password"); err != nil {
			b.Fatal(err)
		}
	}
}
