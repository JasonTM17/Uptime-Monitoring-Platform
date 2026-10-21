// Package config loads and validates process configuration.
//
// Load is a pure function of an environment lookup so table tests can run in
// parallel without mutating process state. Validation is fail-closed: any
// missing required key, malformed value, or violated relationship stops the
// process before it connects or listens. Error messages name configuration
// keys only — they never echo values.
package config

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// Profile selects the resource-default table. Profiles share one codebase
// and one correctness rule; they change capacity numbers only, never policy.
type Profile string

const (
	ProfileLocal  Profile = "local"
	ProfileHosted Profile = "hosted"
)

// Config is the validated, immutable process configuration.
type Config struct {
	Profile   Profile
	HTTP      HTTPConfig
	Database  DatabaseConfig
	Engine    EngineConfig
	Admission AdmissionConfig
	Alloc     AllocConfig
	Notify    NotifyConfig
	Auth      AuthConfig
}

// HTTPConfig bounds the public HTTP server.
type HTTPConfig struct {
	Host              string
	Port              int
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
	MaxJSONBodyBytes  int64
	RequestIDMaxLen   int
	// TrustedProxies lists CIDRs whose forwarded headers are honored.
	// An absent or empty list means trust nothing forwarded.
	TrustedProxies []netip.Prefix
}

// DatabaseConfig holds DSNs and pool bounds. URLs are secrets: required,
// never defaulted, never summarized.
type DatabaseConfig struct {
	URL          string
	EngineURL    string
	MigrationURL string
	MaxConns     int32
	MinConns     int32
	ConnTimeout  time.Duration
	QueryTimeout time.Duration
}

// EngineConfig bounds scheduling and target work.
type EngineConfig struct {
	Workers            int
	QueueSize          int
	CheckInterval      time.Duration
	TargetTimeout      time.Duration
	GlobalMonitorLimit int
	OwnerMonitorLimit  int
}

// AdmissionConfig is the durable rolling-60s admission budget (F02).
// Charges are committed check-run reservations; they are never refunded.
type AdmissionConfig struct {
	GlobalPer60s int
	OwnerPer60s  int
}

// AllocConfig holds the finite allocation ceilings (F03): retained monitors
// and pending/retained notification channels, per owner and global.
type AllocConfig struct {
	RetainedMonitorsOwner  int
	RetainedMonitorsGlobal int
	PendingChannelsOwner   int
	PendingChannelsGlobal  int
	RetainedChannelsOwner  int
	RetainedChannelsGlobal int
}

// AuthConfig bounds password hashing. Argon2id cost is the project
// initial candidate (64MiB/time3/p1); the OWASP floor (19MiB/time2/p1) is
// the validation minimum, never an automatic downgrade target.
type AuthConfig struct {
	ArgonMemoryKiB   uint32
	ArgonTime        uint32
	ArgonParallelism uint8
	ArgonSaltLen     uint32
	ArgonKeyLen      uint32
	HashWorkers      int
}

// NotifyConfig gates notification delivery. The keyring contract is
// reserved here; secret material is parsed only when the feature is
// implemented (C44) — until then, enabling fails closed.
type NotifyConfig struct {
	Enabled bool
}

// Keyring resolves a key version to secret bytes. Reserved for the
// notification channel cipher (F08); implemented at C44.
type Keyring interface {
	Lookup(version string) ([]byte, bool)
	WriteVersion() string
}

// LoadError aggregates every detected problem, keyed by name only.
type LoadError struct {
	problems []string
}

func (e *LoadError) Error() string {
	return "invalid configuration: " + strings.Join(e.problems, "; ")
}

// Problems returns the individual key:reason findings for tests and logging.
func (e *LoadError) Problems() []string { return e.problems }

func (e *LoadError) add(key, reason string) {
	e.problems = append(e.problems, key+": "+reason)
}

// Load builds a Config from lookup (typically os.LookupEnv). It never reads
// process state directly, which keeps tests hermetic and parallel-safe.
func Load(lookup func(string) (string, bool)) (Config, error) {
	errs := &LoadError{}

	profile := ProfileLocal
	if raw, ok := lookup("APP_ENV"); ok && raw != "" {
		profile = Profile(raw)
	}

	var cfg Config
	switch profile {
	case ProfileLocal:
		cfg = localDefaults()
	case ProfileHosted:
		cfg = hostedDefaults()
	default:
		errs.add("APP_ENV", "must be local or hosted")
		cfg = localDefaults()
	}

	envInt(lookup, errs, "HTTP_PORT", &cfg.HTTP.Port)
	envDuration(lookup, errs, "HTTP_READ_HEADER_TIMEOUT", &cfg.HTTP.ReadHeaderTimeout)
	envDuration(lookup, errs, "HTTP_READ_TIMEOUT", &cfg.HTTP.ReadTimeout)
	envDuration(lookup, errs, "HTTP_WRITE_TIMEOUT", &cfg.HTTP.WriteTimeout)
	envDuration(lookup, errs, "HTTP_IDLE_TIMEOUT", &cfg.HTTP.IdleTimeout)
	envDuration(lookup, errs, "HTTP_SHUTDOWN_TIMEOUT", &cfg.HTTP.ShutdownTimeout)
	envInt64(lookup, errs, "HTTP_MAX_JSON_BODY_BYTES", &cfg.HTTP.MaxJSONBodyBytes)
	envInt(lookup, errs, "REQUEST_ID_MAX_LEN", &cfg.HTTP.RequestIDMaxLen)
	if raw, ok := lookup("HTTP_HOST"); ok && raw != "" {
		cfg.HTTP.Host = raw
	}
	if raw, ok := lookup("TRUSTED_PROXIES"); ok {
		cfg.HTTP.TrustedProxies = parseProxies(raw, errs)
	}

	envDuration(lookup, errs, "DB_CONN_TIMEOUT", &cfg.Database.ConnTimeout)
	envInt32(lookup, errs, "DB_MAX_CONNS", &cfg.Database.MaxConns)
	envInt32(lookup, errs, "DB_MIN_CONNS", &cfg.Database.MinConns)
	envDuration(lookup, errs, "DB_QUERY_TIMEOUT", &cfg.Database.QueryTimeout)

	envUint32(lookup, errs, "ARGON2_MEMORY_KIB", &cfg.Auth.ArgonMemoryKiB)
	envUint32(lookup, errs, "ARGON2_TIME", &cfg.Auth.ArgonTime)
	envUint8(lookup, errs, "ARGON2_PARALLELISM", &cfg.Auth.ArgonParallelism)
	envUint32(lookup, errs, "ARGON2_SALT_LEN", &cfg.Auth.ArgonSaltLen)
	envUint32(lookup, errs, "ARGON2_KEY_LEN", &cfg.Auth.ArgonKeyLen)
	envInt(lookup, errs, "AUTH_HASH_WORKERS", &cfg.Auth.HashWorkers)

	envInt(lookup, errs, "ENGINE_WORKERS", &cfg.Engine.Workers)
	envInt(lookup, errs, "ENGINE_QUEUE_SIZE", &cfg.Engine.QueueSize)
	envDuration(lookup, errs, "CHECK_INTERVAL", &cfg.Engine.CheckInterval)
	envDuration(lookup, errs, "CHECK_TARGET_TIMEOUT", &cfg.Engine.TargetTimeout)
	envInt(lookup, errs, "GLOBAL_MONITOR_LIMIT", &cfg.Engine.GlobalMonitorLimit)
	envInt(lookup, errs, "OWNER_MONITOR_LIMIT", &cfg.Engine.OwnerMonitorLimit)

	envInt(lookup, errs, "CHECK_ADMISSIONS_GLOBAL_PER_60S", &cfg.Admission.GlobalPer60s)
	envInt(lookup, errs, "CHECK_ADMISSIONS_OWNER_PER_60S", &cfg.Admission.OwnerPer60s)

	envInt(lookup, errs, "RETAINED_MONITORS_OWNER_LIMIT", &cfg.Alloc.RetainedMonitorsOwner)
	envInt(lookup, errs, "RETAINED_MONITORS_GLOBAL_LIMIT", &cfg.Alloc.RetainedMonitorsGlobal)
	envInt(lookup, errs, "PENDING_CHANNELS_OWNER_LIMIT", &cfg.Alloc.PendingChannelsOwner)
	envInt(lookup, errs, "PENDING_CHANNELS_GLOBAL_LIMIT", &cfg.Alloc.PendingChannelsGlobal)
	envInt(lookup, errs, "RETAINED_CHANNELS_OWNER_LIMIT", &cfg.Alloc.RetainedChannelsOwner)
	envInt(lookup, errs, "RETAINED_CHANNELS_GLOBAL_LIMIT", &cfg.Alloc.RetainedChannelsGlobal)

	if raw, ok := lookup("NOTIFICATIONS_ENABLED"); ok {
		v, err := strconv.ParseBool(raw)
		if err != nil {
			errs.add("NOTIFICATIONS_ENABLED", "must be a boolean")
		} else {
			cfg.Notify.Enabled = v
		}
	}

	cfg.Database.URL = requiredSecret(lookup, errs, "DATABASE_URL")
	cfg.Database.EngineURL = requiredSecret(lookup, errs, "ENGINE_DATABASE_URL")
	cfg.Database.MigrationURL = requiredSecret(lookup, errs, "MIGRATION_DATABASE_URL")

	validate(&cfg, errs)
	if len(errs.problems) > 0 {
		return Config{}, errs
	}
	return cfg, nil
}

// LoadFromEnv loads from the real process environment.
func LoadFromEnv() (Config, error) { return Load(os.LookupEnv) }

func localDefaults() Config {
	return Config{
		Profile: ProfileLocal,
		HTTP: HTTPConfig{
			Host:              "127.0.0.1",
			Port:              8080,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
			ShutdownTimeout:   15 * time.Second,
			MaxJSONBodyBytes:  32 << 10,
			RequestIDMaxLen:   64,
		},
		Database: DatabaseConfig{
			MaxConns:     10,
			MinConns:     1,
			ConnTimeout:  10 * time.Second,
			QueryTimeout: 5 * time.Second,
		},
		Engine: EngineConfig{
			Workers:            10,
			QueueSize:          20,
			CheckInterval:      60 * time.Second,
			TargetTimeout:      5 * time.Second,
			GlobalMonitorLimit: 100,
			OwnerMonitorLimit:  100,
		},
		Admission: AdmissionConfig{GlobalPer60s: 100, OwnerPer60s: 100},
		Alloc: AllocConfig{
			RetainedMonitorsOwner:  100,
			RetainedMonitorsGlobal: 200,
			PendingChannelsOwner:   5,
			PendingChannelsGlobal:  50,
			RetainedChannelsOwner:  10,
			RetainedChannelsGlobal: 100,
		},
		Auth: defaultAuthConfig(),
	}
}

func hostedDefaults() Config {
	return Config{
		Profile: ProfileHosted,
		HTTP: HTTPConfig{
			Host:              "0.0.0.0",
			Port:              8080,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
			ShutdownTimeout:   15 * time.Second,
			MaxJSONBodyBytes:  32 << 10,
			RequestIDMaxLen:   64,
		},
		Database: DatabaseConfig{
			MaxConns:     4,
			MinConns:     0,
			ConnTimeout:  10 * time.Second,
			QueryTimeout: 5 * time.Second,
		},
		Engine: EngineConfig{
			Workers:            2,
			QueueSize:          10,
			CheckInterval:      60 * time.Second,
			TargetTimeout:      5 * time.Second,
			GlobalMonitorLimit: 10,
			OwnerMonitorLimit:  10,
		},
		Admission: AdmissionConfig{GlobalPer60s: 10, OwnerPer60s: 10},
		Alloc: AllocConfig{
			RetainedMonitorsOwner:  20,
			RetainedMonitorsGlobal: 20,
			PendingChannelsOwner:   2,
			PendingChannelsGlobal:  10,
			RetainedChannelsOwner:  4,
			RetainedChannelsGlobal: 20,
		},
		Auth: defaultAuthConfig(),
	}
}

// defaultAuthConfig returns the Argon2id initial candidate: 64MiB /
// time 3 / parallelism 1, 16-byte salt, 32-byte key, at most 2 hash
// workers (bounded admission before expensive KDF work).
func defaultAuthConfig() AuthConfig {
	return AuthConfig{
		ArgonMemoryKiB:   64 * 1024,
		ArgonTime:        3,
		ArgonParallelism: 1,
		ArgonSaltLen:     16,
		ArgonKeyLen:      32,
		HashWorkers:      2,
	}
}

func validate(cfg *Config, errs *LoadError) {
	if cfg.HTTP.Host == "" {
		errs.add("HTTP_HOST", "must not be empty")
	}
	bound(errs, "HTTP_PORT", cfg.HTTP.Port, 1, 65535)
	positive(errs, "HTTP_READ_HEADER_TIMEOUT", cfg.HTTP.ReadHeaderTimeout)
	positive(errs, "HTTP_READ_TIMEOUT", cfg.HTTP.ReadTimeout)
	positive(errs, "HTTP_WRITE_TIMEOUT", cfg.HTTP.WriteTimeout)
	positive(errs, "HTTP_IDLE_TIMEOUT", cfg.HTTP.IdleTimeout)
	positive(errs, "HTTP_SHUTDOWN_TIMEOUT", cfg.HTTP.ShutdownTimeout)
	bound64(errs, "HTTP_MAX_JSON_BODY_BYTES", cfg.HTTP.MaxJSONBodyBytes, 1024, 1<<20)
	bound(errs, "REQUEST_ID_MAX_LEN", cfg.HTTP.RequestIDMaxLen, 8, 128)

	positive(errs, "DB_CONN_TIMEOUT", cfg.Database.ConnTimeout)
	positive(errs, "DB_QUERY_TIMEOUT", cfg.Database.QueryTimeout)
	if cfg.Database.MaxConns < 1 {
		errs.add("DB_MAX_CONNS", "must be >= 1")
	}
	if cfg.Database.MinConns < 0 || cfg.Database.MinConns > cfg.Database.MaxConns {
		errs.add("DB_MIN_CONNS", "must be 0..DB_MAX_CONNS")
	}

	if cfg.Engine.Workers < 1 {
		errs.add("ENGINE_WORKERS", "must be >= 1")
	}
	if cfg.Engine.QueueSize < 0 {
		errs.add("ENGINE_QUEUE_SIZE", "must be >= 0")
	}
	if cfg.Engine.CheckInterval < 60*time.Second {
		errs.add("CHECK_INTERVAL", "must be >= 60s")
	}
	if cfg.Engine.TargetTimeout < time.Second || cfg.Engine.TargetTimeout > 10*time.Second {
		errs.add("CHECK_TARGET_TIMEOUT", "must be 1s..10s")
	}
	bound(errs, "GLOBAL_MONITOR_LIMIT", cfg.Engine.GlobalMonitorLimit, 1, 10000)
	bound(errs, "OWNER_MONITOR_LIMIT", cfg.Engine.OwnerMonitorLimit, 1, 10000)
	if cfg.Engine.OwnerMonitorLimit > cfg.Engine.GlobalMonitorLimit {
		errs.add("OWNER_MONITOR_LIMIT", "must be <= GLOBAL_MONITOR_LIMIT")
	}

	// F02: fixed 60s window, 1..10000, owner <= global.
	bound(errs, "CHECK_ADMISSIONS_GLOBAL_PER_60S", cfg.Admission.GlobalPer60s, 1, 10000)
	bound(errs, "CHECK_ADMISSIONS_OWNER_PER_60S", cfg.Admission.OwnerPer60s, 1, 10000)
	if cfg.Admission.OwnerPer60s > cfg.Admission.GlobalPer60s {
		errs.add("CHECK_ADMISSIONS_OWNER_PER_60S", "must be <= CHECK_ADMISSIONS_GLOBAL_PER_60S")
	}

	// F03: finite ceilings, owner <= global, retained >= live/pending.
	bound(errs, "RETAINED_MONITORS_OWNER_LIMIT", cfg.Alloc.RetainedMonitorsOwner, 1, 100000)
	bound(errs, "RETAINED_MONITORS_GLOBAL_LIMIT", cfg.Alloc.RetainedMonitorsGlobal, 1, 100000)
	bound(errs, "PENDING_CHANNELS_OWNER_LIMIT", cfg.Alloc.PendingChannelsOwner, 1, 10000)
	bound(errs, "PENDING_CHANNELS_GLOBAL_LIMIT", cfg.Alloc.PendingChannelsGlobal, 1, 10000)
	bound(errs, "RETAINED_CHANNELS_OWNER_LIMIT", cfg.Alloc.RetainedChannelsOwner, 1, 10000)
	bound(errs, "RETAINED_CHANNELS_GLOBAL_LIMIT", cfg.Alloc.RetainedChannelsGlobal, 1, 10000)

	// Argon2id: never weaker than the OWASP floor (19MiB/t2/p1), never
	// so large that a config typo becomes a memory bomb.
	if cfg.Auth.ArgonMemoryKiB < 19*1024 || cfg.Auth.ArgonMemoryKiB > 1024*1024 {
		errs.add("ARGON2_MEMORY_KIB", "must be 19456..1048576 KiB")
	}
	boundUint32(errs, "ARGON2_TIME", cfg.Auth.ArgonTime, 2, 16)
	if cfg.Auth.ArgonParallelism < 1 || cfg.Auth.ArgonParallelism > 8 {
		errs.add("ARGON2_PARALLELISM", "must be 1..8")
	}
	boundUint32(errs, "ARGON2_SALT_LEN", cfg.Auth.ArgonSaltLen, 8, 64)
	boundUint32(errs, "ARGON2_KEY_LEN", cfg.Auth.ArgonKeyLen, 16, 64)
	bound(errs, "AUTH_HASH_WORKERS", cfg.Auth.HashWorkers, 1, 8)

	if cfg.Alloc.RetainedMonitorsOwner > cfg.Alloc.RetainedMonitorsGlobal {
		errs.add("RETAINED_MONITORS_OWNER_LIMIT", "must be <= RETAINED_MONITORS_GLOBAL_LIMIT")
	}
	if cfg.Alloc.RetainedMonitorsOwner < cfg.Engine.OwnerMonitorLimit {
		errs.add("RETAINED_MONITORS_OWNER_LIMIT", "must be >= OWNER_MONITOR_LIMIT")
	}
	if cfg.Alloc.RetainedMonitorsGlobal < cfg.Engine.GlobalMonitorLimit {
		errs.add("RETAINED_MONITORS_GLOBAL_LIMIT", "must be >= GLOBAL_MONITOR_LIMIT")
	}
	if cfg.Alloc.PendingChannelsOwner > cfg.Alloc.PendingChannelsGlobal {
		errs.add("PENDING_CHANNELS_OWNER_LIMIT", "must be <= PENDING_CHANNELS_GLOBAL_LIMIT")
	}
	if cfg.Alloc.RetainedChannelsOwner < cfg.Alloc.PendingChannelsOwner {
		errs.add("RETAINED_CHANNELS_OWNER_LIMIT", "must be >= PENDING_CHANNELS_OWNER_LIMIT")
	}
	if cfg.Alloc.RetainedChannelsGlobal < cfg.Alloc.PendingChannelsGlobal {
		errs.add("RETAINED_CHANNELS_GLOBAL_LIMIT", "must be >= PENDING_CHANNELS_GLOBAL_LIMIT")
	}
	if cfg.Alloc.RetainedChannelsOwner > cfg.Alloc.RetainedChannelsGlobal {
		errs.add("RETAINED_CHANNELS_OWNER_LIMIT", "must be <= RETAINED_CHANNELS_GLOBAL_LIMIT")
	}

	if cfg.Notify.Enabled {
		errs.add("NOTIFICATIONS_ENABLED", "notification feature is gated until C44; secret parsing is not implemented")
	}
}

// SafeSummary is an allowlist-built projection safe to log or return in
// diagnostics: names, versions, counts, and listen address only. It is
// constructed field by field — never copy-and-redact, which leaks the next
// secret added to Config.
type SafeSummary struct {
	Profile              string `json:"profile"`
	Listen               string `json:"listen"`
	HTTPTimeouts         string `json:"http_timeouts"`
	MaxJSONBodyBytes     int64  `json:"max_json_body_bytes"`
	TrustedProxies       int    `json:"trusted_proxies"`
	DatabaseConfigured   bool   `json:"database_configured"`
	Workers              int    `json:"workers"`
	QueueSize            int    `json:"queue_size"`
	CheckInterval        string `json:"check_interval"`
	TargetTimeout        string `json:"target_timeout"`
	MonitorLimits        [2]int `json:"monitor_limits"`
	AdmissionsPer60s     [2]int `json:"admissions_per_60s"`
	RetainedMonitors     [2]int `json:"retained_monitors"`
	PendingChannels      [2]int `json:"pending_channels"`
	RetainedChannels     [2]int `json:"retained_channels"`
	NotificationsEnabled bool   `json:"notifications_enabled"`
}

// Summary returns the allowlisted safe projection.
func (c Config) Summary() SafeSummary {
	return SafeSummary{
		Profile:              string(c.Profile),
		Listen:               c.HTTP.Host + ":" + strconv.Itoa(c.HTTP.Port),
		HTTPTimeouts:         fmt.Sprintf("rh=%s r=%s w=%s i=%s sd=%s", c.HTTP.ReadHeaderTimeout, c.HTTP.ReadTimeout, c.HTTP.WriteTimeout, c.HTTP.IdleTimeout, c.HTTP.ShutdownTimeout),
		MaxJSONBodyBytes:     c.HTTP.MaxJSONBodyBytes,
		TrustedProxies:       len(c.HTTP.TrustedProxies),
		DatabaseConfigured:   c.Database.URL != "" && c.Database.EngineURL != "" && c.Database.MigrationURL != "",
		Workers:              c.Engine.Workers,
		QueueSize:            c.Engine.QueueSize,
		CheckInterval:        c.Engine.CheckInterval.String(),
		TargetTimeout:        c.Engine.TargetTimeout.String(),
		MonitorLimits:        [2]int{c.Engine.OwnerMonitorLimit, c.Engine.GlobalMonitorLimit},
		AdmissionsPer60s:     [2]int{c.Admission.OwnerPer60s, c.Admission.GlobalPer60s},
		RetainedMonitors:     [2]int{c.Alloc.RetainedMonitorsOwner, c.Alloc.RetainedMonitorsGlobal},
		PendingChannels:      [2]int{c.Alloc.PendingChannelsOwner, c.Alloc.PendingChannelsGlobal},
		RetainedChannels:     [2]int{c.Alloc.RetainedChannelsOwner, c.Alloc.RetainedChannelsGlobal},
		NotificationsEnabled: c.Notify.Enabled,
	}
}

func requiredSecret(lookup func(string) (string, bool), errs *LoadError, key string) string {
	v, ok := lookup(key)
	if !ok || v == "" {
		errs.add(key, "required")
		return ""
	}
	return v
}

func parseProxies(raw string, errs *LoadError) []netip.Prefix {
	if raw == "" {
		return nil
	}
	var out []netip.Prefix
	for _, part := range strings.Split(raw, ",") {
		p, err := netip.ParsePrefix(strings.TrimSpace(part))
		if err != nil {
			errs.add("TRUSTED_PROXIES", "contains an invalid CIDR")
			return nil
		}
		out = append(out, p)
	}
	return out
}

func envInt(lookup func(string) (string, bool), errs *LoadError, key string, dst *int) {
	raw, ok := lookup(key)
	if !ok || raw == "" {
		return
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		errs.add(key, "must be an integer")
		return
	}
	*dst = v
}

func envInt32(lookup func(string) (string, bool), errs *LoadError, key string, dst *int32) {
	raw, ok := lookup(key)
	if !ok || raw == "" {
		return
	}
	v, err := strconv.ParseInt(raw, 10, 32)
	if err != nil {
		errs.add(key, "must be a 32-bit integer")
		return
	}
	*dst = int32(v)
}

func envUint32(lookup func(string) (string, bool), errs *LoadError, key string, dst *uint32) {
	raw, ok := lookup(key)
	if !ok || raw == "" {
		return
	}
	v, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		errs.add(key, "must be an unsigned 32-bit integer")
		return
	}
	*dst = uint32(v)
}

func envUint8(lookup func(string) (string, bool), errs *LoadError, key string, dst *uint8) {
	raw, ok := lookup(key)
	if !ok || raw == "" {
		return
	}
	v, err := strconv.ParseUint(raw, 10, 8)
	if err != nil {
		errs.add(key, "must be an unsigned 8-bit integer")
		return
	}
	*dst = uint8(v)
}

func envInt64(lookup func(string) (string, bool), errs *LoadError, key string, dst *int64) {
	raw, ok := lookup(key)
	if !ok || raw == "" {
		return
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		errs.add(key, "must be a 64-bit integer")
		return
	}
	*dst = v
}

func envDuration(lookup func(string) (string, bool), errs *LoadError, key string, dst *time.Duration) {
	raw, ok := lookup(key)
	if !ok || raw == "" {
		return
	}
	v, err := time.ParseDuration(raw)
	if err != nil {
		errs.add(key, "must be a duration like 5s or 1m")
		return
	}
	*dst = v
}

func positive(errs *LoadError, key string, v time.Duration) {
	if v <= 0 {
		errs.add(key, "must be > 0")
	}
}

func bound(errs *LoadError, key string, v, lo, hi int) {
	if v < lo || v > hi {
		errs.add(key, "out of allowed range")
	}
}

func boundUint32(errs *LoadError, key string, v uint32, lo, hi uint32) {
	if v < lo || v > hi {
		errs.add(key, "out of allowed range")
	}
}

func bound64(errs *LoadError, key string, v int64, lo, hi int64) {
	if v < lo || v > hi {
		errs.add(key, "out of allowed range")
	}
}
