//go:build integration

package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/auth"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/config"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/platform/database"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, config.DatabaseConfig{
		URL:         testDSN(t),
		MaxConns:    4,
		MinConns:    0,
		ConnTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestIdentityRepository(t *testing.T) {
	repo := auth.NewRepository(testPool(t), 5*time.Second)
	ctx := context.Background()

	t.Run("create and find round-trip", func(t *testing.T) {
		u, err := repo.CreateUser(ctx, "rt@example.com", "$argon2id$fixture", "rt", 77)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if u.Status != auth.UserStatusActive || u.SecurityVersion != 1 {
			t.Fatalf("unexpected defaults %+v", u)
		}
		// 77 differs from the column DEFAULT 10 — proves the caller-stamped
		// quota lands, not the schema fallback.
		if u.MonitorLimit != 77 {
			t.Fatalf("monitor_limit = %d, want stamped quota 77 (not DB default)", u.MonitorLimit)
		}
		byEmail, err := repo.FindUserByEmail(ctx, "rt@example.com")
		if err != nil || byEmail.ID != u.ID {
			t.Fatalf("find by email: %v %+v", err, byEmail)
		}
		byID, err := repo.FindUserByID(ctx, u.ID)
		if err != nil || byID.Email != "rt@example.com" {
			t.Fatalf("find by id: %v %+v", err, byID)
		}
	})

	t.Run("duplicate email maps to ErrDuplicateEmail not 500", func(t *testing.T) {
		if _, err := repo.CreateUser(ctx, "dup@example.com", "h", "", 10); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if _, err := repo.CreateUser(ctx, "dup@example.com", "h", "", 10); !errors.Is(err, auth.ErrDuplicateEmail) {
			t.Fatalf("expected ErrDuplicateEmail, got %v", err)
		}
	})

	t.Run("not found maps to ErrNotFound", func(t *testing.T) {
		if _, err := repo.FindUserByEmail(ctx, "nobody@example.com"); !errors.Is(err, auth.ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}
		if _, err := repo.FindUserByID(ctx, uuid.New()); !errors.Is(err, auth.ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("injection-shaped email stays a parameter", func(t *testing.T) {
		evil := "x' OR '1'='1@example.com"
		if _, err := repo.FindUserByEmail(ctx, evil); !errors.Is(err, auth.ErrNotFound) {
			t.Fatalf("expected ErrNotFound for nonexistent evil email, got %v", err)
		}
	})

	t.Run("query timeout is finite", func(t *testing.T) {
		slow := auth.NewRepository(testPool(t), time.Nanosecond)
		if _, err := slow.FindUserByEmail(ctx, "x@example.com"); err == nil || !errors.Is(err, auth.ErrUnavailable) {
			t.Fatalf("expected bounded failure, got %v", err)
		}
	})
}
