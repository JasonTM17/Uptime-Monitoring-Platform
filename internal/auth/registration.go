package auth

import (
	"context"
	"errors"
	"net/mail"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/config"
)

// Registration policy from the security spec: email is trimmed +
// lowercased (3..254 bytes, no per-provider transforms); password is
// 12..128 Unicode codepoints and at most 1024 bytes, never trimmed,
// normalized, or truncated. No role/status/quota fields are accepted.

const (
	minPasswordRunes  = 12
	maxPasswordRunes  = 128
	maxPasswordByteCp = 1024
	maxEmailBytes     = 254
	minEmailBytes     = 3
	maxDisplayRunes   = 100
)

var ErrEmailTaken = errors.New("email already registered")

// FieldError is a safe 422 payload: bounded per-field messages, never
// echoing the rejected value back.
type FieldError struct {
	Fields map[string]string
}

func (e *FieldError) Error() string { return "validation failed" }

// UserStore is the persistence seam Register depends on. *Repository
// satisfies it; tests substitute fakes.
type UserStore interface {
	CreateUser(ctx context.Context, email, passwordHash, displayName string, monitorLimit int) (User, error)
	FindUserByEmail(ctx context.Context, email string) (User, error)
}

// PasswordHasher is the KDF seam — *Hasher satisfies it. Tests use a
// counting fake to prove malformed input never reaches the KDF.
type PasswordHasher interface {
	HashPassword(ctx context.Context, password string) (string, error)
	VerifyPassword(ctx context.Context, password, storedPHC string) (bool, error)
}

// Store is the combined persistence seam — *Repository satisfies it;
// tests substitute fakes.
type Store interface {
	UserStore
	SessionStore
}

// SessionPolicy carries configured session expiries.
type SessionPolicy struct {
	Absolute time.Duration
	Idle     time.Duration
}

// Service owns identity use cases. Constructed once at composition.
// now is injectable for deterministic expiry tests.
type Service struct {
	store       Store
	hasher      PasswordHasher
	pol         SessionPolicy
	ipLimiter   *attemptLimiter
	acctLimiter *attemptLimiter
	regLimiter  *attemptLimiter
	monLimit    int
	now         func() time.Time
	dummyMu     sync.Mutex
	dummy       string
}

// NewService builds the identity facade. defaultMonitorLimit is the
// per-user monitor quota stamped at registration — the users row is
// the runtime authority (admins may adjust per user), config only
// supplies the default.
func NewService(store Store, hasher PasswordHasher, cfg config.AuthConfig, defaultMonitorLimit int) *Service {
	return &Service{
		store:  store,
		hasher: hasher,
		pol: SessionPolicy{
			Absolute: cfg.SessionAbsoluteExpiry,
			Idle:     cfg.SessionIdleExpiry,
		},
		ipLimiter:   newAttemptLimiter(cfg.LoginIPAttemptsPerMin, time.Minute, cfg.LimiterMaxKeys),
		acctLimiter: newAttemptLimiter(cfg.LoginAccountAttemptsPer15M, 15*time.Minute, cfg.LimiterMaxKeys),
		regLimiter:  newAttemptLimiter(cfg.RegisterIPAttemptsPerMin, time.Minute, cfg.LimiterMaxKeys),
		monLimit:    defaultMonitorLimit,
		now:         time.Now,
	}
}

// CheckRegisterBudget applies the per-IP register budget BEFORE any
// KDF work — /auth/register is unauthenticated, so without this an
// attacker can park the (bounded) Argon2 workers and starve logins.
// It deliberately shares no bucket with the login limiter.
func (s *Service) CheckRegisterBudget(clientIP string) error {
	if ok, wait := s.regLimiter.allow(loginKey("regip", clientIP)); !ok {
		return &RateLimitedError{RetryAfter: wait}
	}
	return nil
}

// PublicUser is the only shape that may leave the service layer — it
// carries no password hash, token, or internal flags.
type PublicUser struct {
	ID          uuid.UUID `json:"id"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

func publicUser(u User) PublicUser {
	return PublicUser{ID: u.ID, Email: u.Email, DisplayName: u.DisplayName,
		Status: u.Status, CreatedAt: u.CreatedAt}
}

// RegisterInput is the exact accepted body shape. The decoder rejects
// every other key (role/status/admin/quota injection is a 400).
type RegisterInput struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name,omitempty"`
}

// NormalizeEmail trims and lowercases per the canonical-email policy.
// No Gmail-style dot/plus stripping — uniqueness is the DB's CHECK on
// lower(btrim(email)), and this is the only transform that matches it.
func NormalizeEmail(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

func validEmail(email string) bool {
	if len(email) < minEmailBytes || len(email) > maxEmailBytes {
		return false
	}
	a, err := mail.ParseAddress(email)
	return err == nil && a.Address == email
}

// ValidateRegistration returns nil or *FieldError. It runs BEFORE any
// hashing so malformed input never consumes KDF budget.
func ValidateRegistration(in RegisterInput) error {
	fields := map[string]string{}
	email := NormalizeEmail(in.Email)
	if !validEmail(email) {
		fields["email"] = "must be a valid email address"
	}
	runes := utf8.RuneCountInString(in.Password)
	switch {
	case runes < minPasswordRunes:
		fields["password"] = "must be at least 12 characters"
	case runes > maxPasswordRunes || len(in.Password) > maxPasswordByteCp:
		fields["password"] = "must be at most 128 characters"
	}
	if utf8.RuneCountInString(in.DisplayName) > maxDisplayRunes {
		fields["display_name"] = "must be at most 100 characters"
	}
	if len(fields) > 0 {
		return &FieldError{Fields: fields}
	}
	return nil
}

// Register validates, hashes, then inserts. The unique canonical-email
// constraint — not a check-then-insert — is the duplicate guard, so a
// same-email race produces exactly one account.
func (s *Service) Register(ctx context.Context, in RegisterInput) (PublicUser, error) {
	if err := ValidateRegistration(in); err != nil {
		return PublicUser{}, err
	}
	hash, err := s.hasher.HashPassword(ctx, in.Password)
	if err != nil {
		return PublicUser{}, err
	}
	u, err := s.store.CreateUser(ctx, NormalizeEmail(in.Email), hash,
		strings.TrimSpace(in.DisplayName), s.monLimit)
	if err != nil {
		if errors.Is(err, ErrDuplicateEmail) {
			return PublicUser{}, ErrEmailTaken
		}
		return PublicUser{}, err
	}
	return publicUser(u), nil
}
