package database

import (
	"context"
	"testing"
	"time"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/config"
)

func testDBConfig(url string) config.DatabaseConfig {
	return config.DatabaseConfig{
		URL:         url,
		MaxConns:    2,
		MinConns:    0,
		ConnTimeout: 2 * time.Second,
	}
}

func TestOpenRejectsBadDSN(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := Open(ctx, testDBConfig("not a dsn")); err == nil {
		t.Fatal("expected parse error for malformed DSN")
	}
}

func TestOpenHonorsConnTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// RFC5737 TEST-NET — nothing listens; pool creation itself is lazy so
	// this only proves config accepted the bounds, not a live dial.
	pool, err := Open(ctx, testDBConfig("postgres://u:p@192.0.2.1:1/db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	pool.Close()
}
