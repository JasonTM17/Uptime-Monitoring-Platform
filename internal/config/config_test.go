package config

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// baseEnv returns a lookup seeded with the three required DSNs.
// Each test case merges overrides on top; a test never touches os.Environ.
func baseEnv(overrides map[string]string) func(string) (string, bool) {
	env := map[string]string{
		"DATABASE_URL":           "postgres://u:p@127.0.0.1:54320/u",
		"ENGINE_DATABASE_URL":    "postgres://u:p@127.0.0.1:54320/u",
		"MIGRATION_DATABASE_URL": "postgres://u:p@127.0.0.1:54320/u",
	}
	for k, v := range overrides {
		env[k] = v
	}
	return func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}
}

func problems(err error) string {
	le, ok := err.(*LoadError)
	if !ok {
		return ""
	}
	return strings.Join(le.Problems(), "|")
}

func TestLoad(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		overrides map[string]string
		check     func(t *testing.T, c Config)
	}{
		{
			name:      "local defaults resolve without optional env",
			overrides: nil,
			check: func(t *testing.T, c Config) {
				if c.Profile != ProfileLocal {
					t.Fatalf("profile = %q", c.Profile)
				}
				if c.Engine.Workers != 10 || c.Engine.QueueSize != 20 {
					t.Fatalf("engine = %d/%d", c.Engine.Workers, c.Engine.QueueSize)
				}
				if c.Admission.GlobalPer60s != 100 || c.Admission.OwnerPer60s != 100 {
					t.Fatalf("admission = %d/%d", c.Admission.OwnerPer60s, c.Admission.GlobalPer60s)
				}
				if len(c.HTTP.TrustedProxies) != 0 {
					t.Fatal("absent TRUSTED_PROXIES must mean trust none")
				}
			},
		},
		{
			name:      "hosted profile selects scaled table",
			overrides: map[string]string{"APP_ENV": "hosted"},
			check: func(t *testing.T, c Config) {
				if c.Engine.GlobalMonitorLimit != 10 || c.Admission.GlobalPer60s != 10 {
					t.Fatalf("hosted caps = %d/%d", c.Engine.GlobalMonitorLimit, c.Admission.GlobalPer60s)
				}
			},
		},
		{
			name:      "env overrides beat profile defaults",
			overrides: map[string]string{"ENGINE_WORKERS": "4", "HTTP_PORT": "9090"},
			check: func(t *testing.T, c Config) {
				if c.Engine.Workers != 4 || c.HTTP.Port != 9090 {
					t.Fatalf("overrides not applied: %+v", c.Engine)
				}
			},
		},
		{
			name:      "valid CIDR list parses",
			overrides: map[string]string{"TRUSTED_PROXIES": "10.0.0.0/8, 192.168.0.0/16"},
			check: func(t *testing.T, c Config) {
				if len(c.HTTP.TrustedProxies) != 2 {
					t.Fatalf("proxies = %v", c.HTTP.TrustedProxies)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := Load(baseEnv(tc.overrides))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			tc.check(t, c)
		})
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		overrides map[string]string
		wantKey   string // a key name expected inside the aggregated error
	}{
		{"missing DATABASE_URL fails closed", map[string]string{"DATABASE_URL": ""}, "DATABASE_URL"},
		{"missing ENGINE_DATABASE_URL fails closed", map[string]string{"ENGINE_DATABASE_URL": ""}, "ENGINE_DATABASE_URL"},
		{"zero workers rejected", map[string]string{"ENGINE_WORKERS": "0"}, "ENGINE_WORKERS"},
		{"negative queue rejected", map[string]string{"ENGINE_QUEUE_SIZE": "-1"}, "ENGINE_QUEUE_SIZE"},
		{"bad duration rejected", map[string]string{"HTTP_READ_TIMEOUT": "soon"}, "HTTP_READ_TIMEOUT"},
		{"check interval below 60s rejected", map[string]string{"CHECK_INTERVAL": "30s"}, "CHECK_INTERVAL"},
		{"target timeout above 10s rejected", map[string]string{"CHECK_TARGET_TIMEOUT": "11s"}, "CHECK_TARGET_TIMEOUT"},
		{"unknown profile rejected", map[string]string{"APP_ENV": "staging"}, "APP_ENV"},
		{"invalid proxy CIDR rejected", map[string]string{"TRUSTED_PROXIES": "10.0.0.0"}, "TRUSTED_PROXIES"},
		{"notifications gated until C44", map[string]string{"NOTIFICATIONS_ENABLED": "true"}, "NOTIFICATIONS_ENABLED"},
		{"non-integer rejected", map[string]string{"ENGINE_WORKERS": "many"}, "ENGINE_WORKERS"},
		{"port zero rejected", map[string]string{"HTTP_PORT": "0"}, "HTTP_PORT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Load(baseEnv(tc.overrides))
			if err == nil {
				t.Fatal("expected validation failure")
			}
			if !strings.Contains(problems(err), tc.wantKey) {
				t.Fatalf("error missing key %q: %v", tc.wantKey, err)
			}
		})
	}
}

func TestResourceBudgetConfig(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		overrides map[string]string
		wantKey   string
	}{
		{"zero admission global", map[string]string{"CHECK_ADMISSIONS_GLOBAL_PER_60S": "0"}, "CHECK_ADMISSIONS_GLOBAL_PER_60S"},
		{"overflow admission global", map[string]string{"CHECK_ADMISSIONS_GLOBAL_PER_60S": "10001"}, "CHECK_ADMISSIONS_GLOBAL_PER_60S"},
		{"owner admission above global", map[string]string{"CHECK_ADMISSIONS_GLOBAL_PER_60S": "50"}, "CHECK_ADMISSIONS_OWNER_PER_60S"},
		{"zero retained monitors", map[string]string{"RETAINED_MONITORS_GLOBAL_LIMIT": "0"}, "RETAINED_MONITORS_GLOBAL_LIMIT"},
		{"owner retained above global", map[string]string{"RETAINED_MONITORS_GLOBAL_LIMIT": "50"}, "RETAINED_MONITORS_OWNER_LIMIT"},
		{"retained below live ceiling", map[string]string{"RETAINED_MONITORS_OWNER_LIMIT": "50"}, "RETAINED_MONITORS_OWNER_LIMIT"},
		{"pending owner above global", map[string]string{"PENDING_CHANNELS_GLOBAL_LIMIT": "2"}, "PENDING_CHANNELS_OWNER_LIMIT"},
		{"retained channels below pending", map[string]string{"RETAINED_CHANNELS_OWNER_LIMIT": "2"}, "RETAINED_CHANNELS_OWNER_LIMIT"},
		{"retained channel owner above global", map[string]string{"RETAINED_CHANNELS_GLOBAL_LIMIT": "5"}, "RETAINED_CHANNELS_OWNER_LIMIT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Load(baseEnv(tc.overrides))
			if err == nil {
				t.Fatal("expected fail-closed on invalid resource relationship")
			}
			if !strings.Contains(problems(err), tc.wantKey) {
				t.Fatalf("error missing key %q: %v", tc.wantKey, err)
			}
		})
	}
}

func TestSafeSummary(t *testing.T) {
	t.Parallel()
	const sentinel = "s3cr3t-value-never-log"
	c, err := Load(baseEnv(map[string]string{
		"DATABASE_URL":           "postgres://u:" + sentinel + "@127.0.0.1/db",
		"ENGINE_DATABASE_URL":    "postgres://u:" + sentinel + "@127.0.0.1/db",
		"MIGRATION_DATABASE_URL": "postgres://u:" + sentinel + "@127.0.0.1/db",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	sum := c.Summary()
	raw, err := json.Marshal(sum)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(sentinel)) {
		t.Fatal("summary leaked a secret value")
	}
	if !sum.DatabaseConfigured {
		t.Fatal("summary should report database configured without the DSN")
	}
	// And the error path: a missing required key must not echo values either.
	_, err = Load(baseEnv(map[string]string{"DATABASE_URL": ""}))
	if err == nil || strings.Contains(err.Error(), sentinel) {
		t.Fatalf("error path leaked or missing: %v", err)
	}
}
