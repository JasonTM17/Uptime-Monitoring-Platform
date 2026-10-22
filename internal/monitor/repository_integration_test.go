//go:build integration

package monitor_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/monitor"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("TEST_DATABASE_URL is required for integration tests (point it at the disposable postgres-test database)")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

var fieldSeq atomic.Int64

func mkOwner(t *testing.T, pool *pgxpool.Pool, limit int) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO uptime.users (id,email,password_hash,monitor_limit)
		 VALUES ($1,$2,'$h',$3)`, id,
		fmt.Sprintf("mon-%s@x.co", id.String()[:8]), limit)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

func setUserStatus(t *testing.T, pool *pgxpool.Pool, id uuid.UUID, status string) {
	t.Helper()
	// users CHECK couples status and disabled_at — set both together.
	_, err := pool.Exec(context.Background(),
		`UPDATE uptime.users SET status=$2,
		   disabled_at = CASE WHEN $2='DISABLED' THEN now() ELSE NULL END
		 WHERE id=$1`, id, status)
	if err != nil {
		t.Fatalf("set status: %v", err)
	}
}

func seedBudget(t *testing.T, pool *pgxpool.Pool, global int) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO uptime.quota_budgets (id,global_monitor_limit)
		 VALUES (1,$1) ON CONFLICT (id) DO UPDATE
		 SET global_monitor_limit=$1`, global); err != nil {
		t.Fatalf("seed budget: %v", err)
	}
}

func dropBudget(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`DELETE FROM uptime.quota_budgets WHERE id=1`); err != nil {
		t.Fatalf("drop budget: %v", err)
	}
}

func wf() monitor.WriteFields {
	n := fieldSeq.Add(1)
	return monitor.WriteFields{
		Name:            fmt.Sprintf("m-%d", n),
		TargetURL:       "https://example.com/health",
		IntervalSeconds: 60, TimeoutSeconds: 5,
	}
}

func caps(owner, global int) monitor.Caps {
	return monitor.Caps{RetainedOwner: owner, RetainedGlobal: global}
}

func TestMonitorRepository(t *testing.T) {
	pool := testPool(t)
	repo := monitor.NewRepository(pool, 10*time.Second)
	ctx := context.Background()
	// Big enough ceilings that only the cap under test binds.
	bigCaps := caps(100000, 100000)

	t.Run("create stamps defaults and fences off client fields", func(t *testing.T) {
		seedBudget(t, pool, 1000)
		owner := mkOwner(t, pool, 100)
		m, err := repo.CreateMonitor(ctx, owner, wf(), bigCaps)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if m.Generation != 1 || m.Health != monitor.HealthUnknown ||
			m.Method != "GET" || m.IsPaused || m.DeletedAt != nil ||
			m.FailureStreak != 0 || m.LastReservedSeq != 0 {
			t.Fatalf("bad defaults %+v", m)
		}
		if m.NextCheckAt.IsZero() {
			t.Fatal("next_check_at not set")
		}
	})

	t.Run("missing quota budget fails closed", func(t *testing.T) {
		// DELETE + attempt in ONE tx: a parallel package's
		// EnsureQuotaBudget INSERT blocks on the pending delete and can
		// only land after rollback — the window can't be raced, and the
		// row is restored without a reseed.
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx,
			`DELETE FROM uptime.quota_budgets WHERE id=1`); err != nil {
			t.Fatalf("drop budget: %v", err)
		}
		owner := mkOwner(t, pool, 100)
		_, err = repo.CreateMonitorTx(ctx, tx, owner, 100, wf(), bigCaps)
		if !errors.Is(err, monitor.ErrBudgetMissing) {
			t.Fatalf("want ErrBudgetMissing, got %v", err)
		}
	})

	t.Run("owner live cap binds and counts paused rows", func(t *testing.T) {
		seedBudget(t, pool, 1000)
		owner := mkOwner(t, pool, 1)
		m1, err := repo.CreateMonitor(ctx, owner, wf(), bigCaps)
		if err != nil {
			t.Fatalf("first create: %v", err)
		}
		if _, err := repo.SetMonitorPaused(ctx, owner, m1.ID, 1, true); err != nil {
			t.Fatalf("pause: %v", err)
		}
		// Paused still occupies the live slot (spec: quota counts
		// every nondeleted monitor including paused).
		_, err = repo.CreateMonitor(ctx, owner, wf(), bigCaps)
		if !errors.Is(err, monitor.ErrQuotaOwner) {
			t.Fatalf("want ErrQuotaOwner, got %v", err)
		}
	})

	t.Run("global live cap binds across owners", func(t *testing.T) {
		// Recount from a known baseline: count current live rows and
		// pin the global cap at exactly that count so the next create
		// anywhere must fail.
		var liveN int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM uptime.monitors WHERE deleted_at IS NULL`).Scan(&liveN); err != nil {
			t.Fatalf("count: %v", err)
		}
		seedBudget(t, pool, liveN)
		owner := mkOwner(t, pool, 100)
		_, err := repo.CreateMonitor(ctx, owner, wf(), bigCaps)
		if !errors.Is(err, monitor.ErrQuotaGlobal) {
			t.Fatalf("want ErrQuotaGlobal, got %v", err)
		}
		seedBudget(t, pool, 1000)
	})

	t.Run("retained cap counts tombstones", func(t *testing.T) {
		seedBudget(t, pool, 1000)
		owner := mkOwner(t, pool, 100)
		tight := caps(1, 100000) // retained owner cap = 1
		m1, err := repo.CreateMonitor(ctx, owner, wf(), tight)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if err := repo.SoftDeleteMonitor(ctx, owner, m1.ID, m1.Generation); err != nil {
			t.Fatalf("delete: %v", err)
		}
		// Live slot freed (delete released it) but the tombstone still
		// occupies the retained slot — second create must hit
		// ALLOCATION, not live quota.
		_, err = repo.CreateMonitor(ctx, owner, wf(), tight)
		if !errors.Is(err, monitor.ErrQuotaRetained) {
			t.Fatalf("want ErrQuotaRetained, got %v", err)
		}
	})

	t.Run("disabled owner rejected at mutation time", func(t *testing.T) {
		seedBudget(t, pool, 1000)
		owner := mkOwner(t, pool, 100)
		setUserStatus(t, pool, owner, "DISABLED")
		_, err := repo.CreateMonitor(ctx, owner, wf(), bigCaps)
		if !errors.Is(err, monitor.ErrActorInactive) {
			t.Fatalf("want ErrActorInactive, got %v", err)
		}
	})

	t.Run("final-slot race admits exactly one", func(t *testing.T) {
		seedBudget(t, pool, 1000)
		owner := mkOwner(t, pool, 1) // exactly one live slot
		const racers = 4
		start := make(chan struct{})
		var wg sync.WaitGroup
		wins, losses := make(chan error, racers), make(chan error, racers)
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, err := repo.CreateMonitor(ctx, owner, wf(), bigCaps)
				if err == nil {
					wins <- nil
				} else {
					losses <- err
				}
			}()
		}
		close(start)
		wg.Wait()
		close(wins)
		close(losses)
		w, l := len(wins), 0
		for err := range losses {
			l++
			if !errors.Is(err, monitor.ErrQuotaOwner) {
				t.Fatalf("loser got %v, want ErrQuotaOwner", err)
			}
		}
		if w != 1 || l != racers-1 {
			t.Fatalf("wins=%d losses=%d, want exactly 1 win", w, l)
		}
	})

	t.Run("get is indistinguishable for foreign and missing", func(t *testing.T) {
		owner := mkOwner(t, pool, 100)
		other := mkOwner(t, pool, 100)
		m, err := repo.CreateMonitor(ctx, owner, wf(), bigCaps)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if _, err := repo.GetMonitor(ctx, other, m.ID); !errors.Is(err, monitor.ErrMonitorNotFound) {
			t.Fatalf("foreign read: %v", err)
		}
		if _, err := repo.GetMonitor(ctx, owner, uuid.New()); !errors.Is(err, monitor.ErrMonitorNotFound) {
			t.Fatalf("missing read: %v", err)
		}
	})

	t.Run("update bumps generation and rejects stale fence", func(t *testing.T) {
		owner := mkOwner(t, pool, 100)
		m, _ := repo.CreateMonitor(ctx, owner, wf(), bigCaps)
		in := wf()
		in.Name = "renamed"
		up, err := repo.UpdateMonitor(ctx, owner, m.ID, m.Generation, in)
		if err != nil {
			t.Fatalf("update: %v", err)
		}
		if up.Generation != m.Generation+1 || up.Name != "renamed" ||
			up.Health != monitor.HealthUnknown || up.NextCheckAt != m.NextCheckAt {
			t.Fatalf("bad update %+v", up)
		}
		// Replaying the old generation must conflict, not silently win.
		_, err = repo.UpdateMonitor(ctx, owner, m.ID, m.Generation, in)
		if !errors.Is(err, monitor.ErrGenerationConflict) {
			t.Fatalf("want conflict, got %v", err)
		}
	})

	t.Run("pause keeps health and resume only marks eligibility", func(t *testing.T) {
		owner := mkOwner(t, pool, 100)
		m, _ := repo.CreateMonitor(ctx, owner, wf(), bigCaps)
		p, err := repo.SetMonitorPaused(ctx, owner, m.ID, m.Generation, true)
		if err != nil {
			t.Fatalf("pause: %v", err)
		}
		if !p.IsPaused || p.Health != monitor.HealthUnknown ||
			p.Generation != m.Generation+1 || p.NextCheckAt != m.NextCheckAt {
			t.Fatalf("pause fabricated state %+v", p)
		}
		r, err := repo.SetMonitorPaused(ctx, owner, m.ID, p.Generation, false)
		if err != nil {
			t.Fatalf("resume: %v", err)
		}
		if r.IsPaused || r.Health != monitor.HealthUnknown ||
			r.SuccessStreak != 0 || r.FailureStreak != 0 ||
			r.Generation != p.Generation+1 {
			t.Fatalf("resume fabricated state %+v", r)
		}

		t.Run("pause closes the open schedule segment", func(t *testing.T) {
			owner := mkOwner(t, pool, 100)
			m, _ := repo.CreateMonitor(ctx, owner, wf(), bigCaps)
			// Engine owns segment lifecycle — seed the open segment
			// the first reserve would create.
			if _, err := pool.Exec(ctx, `
				INSERT INTO uptime.schedule_segments
				  (id,monitor_id,generation,starts_at,interval_seconds)
				VALUES (gen_random_uuid(),$1,$2,now(),60)`,
				m.ID, m.Generation); err != nil {
				t.Fatal(err)
			}
			var open int
			p, err := repo.SetMonitorPaused(ctx, owner, m.ID, m.Generation, true)
			if err != nil {
				t.Fatalf("pause: %v", err)
			}
			var endsAt *time.Time
			if err := pool.QueryRow(ctx, `
			SELECT max(ends_at) FROM uptime.schedule_segments
			WHERE monitor_id=$1`, m.ID).Scan(&endsAt); err != nil {
				t.Fatal(err)
			}
			if endsAt == nil {
				t.Fatal("pause left the segment open — paused time would " +
					"enter the expected-slot denominator")
			}
			if err := pool.QueryRow(ctx, `
			SELECT count(*) FROM uptime.schedule_segments
			WHERE monitor_id=$1 AND ends_at IS NULL`, m.ID).
				Scan(&open); err != nil || open != 0 {
				t.Fatalf("still %d open segments err=%v", open, err)
			}
			// Resume leaves coverage closed; the next reserve opens a
			// fresh segment — the pause window never becomes expected.
			if _, err := repo.SetMonitorPaused(ctx, owner, m.ID,
				p.Generation, false); err != nil {
				t.Fatalf("resume: %v", err)
			}
			if err := pool.QueryRow(ctx, `
			SELECT count(*) FROM uptime.schedule_segments
			WHERE monitor_id=$1 AND ends_at IS NULL`, m.ID).
				Scan(&open); err != nil || open != 0 {
				t.Fatalf("resume re-opened a segment: %d err=%v", open, err)
			}
		})
		// Resume marks eligibility only — no check sample may appear.
		if r.LastCheckedAt != nil || r.LastResponseTimeMs != nil ||
			r.LastErrorType != nil {
			t.Fatalf("resume wrote check state %+v", r)
		}
		if r.NextCheckAt.Before(p.NextCheckAt) {
			t.Fatal("resume moved next_check_at backwards")
		}
	})

	t.Run("delete tombstones then reads as missing", func(t *testing.T) {
		owner := mkOwner(t, pool, 100)
		m, _ := repo.CreateMonitor(ctx, owner, wf(), bigCaps)
		if err := repo.SoftDeleteMonitor(ctx, owner, m.ID, m.Generation); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if _, err := repo.GetMonitor(ctx, owner, m.ID); !errors.Is(err, monitor.ErrMonitorNotFound) {
			t.Fatalf("deleted read: %v", err)
		}
		// Stale-generation delete on a tombstone also reads missing.
		if err := repo.SoftDeleteMonitor(ctx, owner, m.ID, m.Generation); !errors.Is(err, monitor.ErrMonitorNotFound) {
			t.Fatalf("re-delete: %v", err)
		}
	})

	t.Run("list pages owner scope newest-first", func(t *testing.T) {
		owner := mkOwner(t, pool, 100)
		other := mkOwner(t, pool, 100)
		for i := 0; i < 3; i++ {
			if _, err := repo.CreateMonitor(ctx, owner, wf(), bigCaps); err != nil {
				t.Fatalf("seed %d: %v", i, err)
			}
		}
		if _, err := repo.CreateMonitor(ctx, other, wf(), bigCaps); err != nil {
			t.Fatalf("other seed: %v", err)
		}
		page1, err := repo.ListMonitors(ctx, owner, monitor.Cursor{}, monitor.ListFilter{}, 2)
		if err != nil || len(page1) != 2 {
			t.Fatalf("page1: %v len=%d", err, len(page1))
		}
		last := page1[len(page1)-1]
		page2, err := repo.ListMonitors(ctx, owner,
			monitor.Cursor{CreatedAt: last.CreatedAt, ID: last.ID, Valid: true}, monitor.ListFilter{}, 10)
		if err != nil || len(page2) != 1 {
			t.Fatalf("page2: %v len=%d", err, len(page2))
		}
		for _, m := range append(page1, page2...) {
			if m.UserID != owner {
				t.Fatalf("foreign row leaked %+v", m)
			}
		}
		// newest-first ordering within page1
		if page1[0].CreatedAt.Before(page1[1].CreatedAt) {
			t.Fatal("page order not newest-first")
		}
	})
}

func TestEnsureQuotaBudget(t *testing.T) {
	pool := testPool(t)
	repo := monitor.NewRepository(pool, 5*time.Second)
	ctx := context.Background()

	dropBudget(t, pool)
	if err := repo.EnsureQuotaBudget(ctx, 42); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	var got int
	if err := pool.QueryRow(ctx,
		`SELECT global_monitor_limit FROM uptime.quota_budgets WHERE id=1`).Scan(&got); err != nil || got != 42 {
		t.Fatalf("seed %d %v", got, err)
	}
	// Second ensure keeps an operator-adjusted row authoritative.
	if _, err := pool.Exec(ctx,
		`UPDATE uptime.quota_budgets SET global_monitor_limit=7 WHERE id=1`); err != nil {
		t.Fatalf("adjust: %v", err)
	}
	if err := repo.EnsureQuotaBudget(ctx, 42); err != nil {
		t.Fatalf("re-ensure: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT global_monitor_limit FROM uptime.quota_budgets WHERE id=1`).Scan(&got); err != nil || got != 7 {
		t.Fatalf("ensure clobbered adjusted row: %d", got)
	}
	seedBudget(t, pool, 1000)
}
