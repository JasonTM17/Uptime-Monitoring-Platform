// Package database owns the shared pgx pool lifecycle. It never logs DSN
// material and keeps every wait bounded by validated config.
package database

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/config"
)

// Open creates a bounded pgxpool. Callers own Close; the pool is not a
// goroutine pool — connection acquisition still honors ctx deadlines.
func Open(ctx context.Context, cfg config.DatabaseConfig) (*pgxpool.Pool, error) {
	pc, err := pgxpool.ParseConfig(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("parse database config: %w", err)
	}
	pc.MaxConns = cfg.MaxConns
	pc.MinConns = cfg.MinConns
	pc.ConnConfig.ConnectTimeout = cfg.ConnTimeout
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, fmt.Errorf("create database pool: %w", err)
	}
	return pool, nil
}

// Ping is the readiness probe shape: bounded by the caller's ctx.
func Ping(pool *pgxpool.Pool) func(context.Context) error {
	return func(ctx context.Context) error {
		if err := pool.Ping(ctx); err != nil {
			return fmt.Errorf("database ping: %w", err)
		}
		return nil
	}
}
