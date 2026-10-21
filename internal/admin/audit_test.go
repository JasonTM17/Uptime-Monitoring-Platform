package admin_test

import (
	"testing"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/admin"
)

func TestAuditRedaction(t *testing.T) {
	const canary = "canary-secret-9f8e7d6c"
	diff := map[string]any{
		"display_name":          "Alice",
		"status":                map[string]any{"before": "ACTIVE", "after": "DISABLED"},
		"version":               float64(3),
		"reason":                "abuse report #41",
		"password":              canary,
		"password_hash":         canary,
		"session_token":         canary,
		"bot_token":             canary,
		"encrypted_destination": canary,
		"csrf_token":            canary,
		"details": map[string]any{
			"note":          "ok",
			"api_key":       canary,
			"totp_seed":     canary,
			"authorization": canary,
			"list":          []any{canary, map[string]any{"token_hash": canary, "n": 1}},
		},
	}
	out := admin.RedactAuditDiff(diff)

	if out["display_name"] != "Alice" || out["version"] != float64(3) {
		t.Fatalf("safe fields dropped: %v", out)
	}
	for _, k := range []string{
		"password", "password_hash", "session_token", "bot_token",
		"encrypted_destination", "csrf_token",
	} {
		if out[k] != "[REDACTED]" {
			t.Fatalf("key %s not redacted: %v", k, out[k])
		}
	}
	inner := out["details"].(map[string]any)
	if inner["note"] != "ok" {
		t.Fatal("nested safe field dropped")
	}
	for _, k := range []string{"api_key", "totp_seed", "authorization"} {
		if inner[k] != "[REDACTED]" {
			t.Fatalf("nested key %s not redacted", k)
		}
	}
	list := inner["list"].([]any)
	if list[0] != canary {
		t.Fatal("positional array values are not keyed — left alone")
	}
	if list[1].(map[string]any)["token_hash"] != "[REDACTED]" {
		t.Fatal("nested map in array not redacted")
	}
	if list[1].(map[string]any)["n"] != 1 {
		t.Fatal("nested safe value dropped")
	}
	// Original untouched — pure copy, no mutation.
	if diff["password"] != canary {
		t.Fatal("RedactAuditDiff mutated its input")
	}
}
