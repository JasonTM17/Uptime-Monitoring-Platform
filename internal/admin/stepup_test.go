package admin_test

import (
	"testing"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/admin"
)

// TestStepupRedaction proves the response persisted for replay is
// sanitized at the boundary — a secret-shaped field in the caller's
// DTO can never become a stored replay blob.
func TestStepupRedaction(t *testing.T) {
	resp := map[string]any{
		"status":          "paused",
		"version":         4,
		"session_token":   "leak",
		"encrypted_field": "leak",
	}
	out := admin.RedactAuditDiff(resp)
	if out["status"] != "paused" || out["version"] != 4 {
		t.Fatal("safe response fields dropped")
	}
	if out["session_token"] != "[REDACTED]" || out["encrypted_field"] != "[REDACTED]" {
		t.Fatalf("replay response not sanitized: %v", out)
	}
}

// TestRecentAuthBounds covers the pure bounds logic callers rely on:
// TTL is the contract boundary.
func TestRecentAuthBounds(t *testing.T) {
	if admin.RecentAuthTTL.Minutes() != 5 {
		t.Fatalf("RecentAuthTTL=%v, want 5m", admin.RecentAuthTTL)
	}
	if admin.IdempotencyTTL.Hours() != 24 {
		t.Fatalf("IdempotencyTTL=%v, want 24h", admin.IdempotencyTTL)
	}
	if admin.MaxIdempotencyKey != 128 {
		t.Fatalf("MaxIdempotencyKey=%d", admin.MaxIdempotencyKey)
	}
}
