package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// Login failure surface is deliberately uniform: unknown email,
// disabled account, and wrong password all produce ErrBadCredentials
// after running an equivalent KDF path (a dummy hash stands in for
// unknown users), so timing/oracle differences stay below noise.

var ErrBadCredentials = errors.New("invalid credentials")

// RateLimitedError carries a bounded, client-safe Retry-After.
type RateLimitedError struct {
	RetryAfter time.Duration
}

func (e *RateLimitedError) Error() string { return "too many attempts" }

// LoginInput is the accepted body shape (decoder rejects other keys).
type LoginInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// loginKey hashes the identity before it enters the limiter map — raw
// emails/IPs never sit in limiter keys or log labels.
func loginKey(kind, raw string) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + raw))
	return kind + ":" + hex.EncodeToString(sum[:16])
}

var dummyOnce struct {
	sync.Once
	hash string
	err  error
}

// dummyHash returns a lazily-generated PHC so unknown-email attempts
// still execute a real Argon2id verification (uniform KDF path).
func (s *Service) dummyHash() (string, error) {
	dummyOnce.Do(func() {
		dummyOnce.hash, dummyOnce.err = s.hasher.HashPassword(context.Background(),
			"dummy-password-for-unknown-users")
	})
	return dummyOnce.hash, dummyOnce.err
}

// Login authenticates email+password under IP and account attempt
// budgets, then issues a fresh session (rotation: every login mints a
// new token; the caller never accepts a client-chosen session ID).
// clientKey is the handler-resolved client IP string.
func (s *Service) Login(ctx context.Context, in LoginInput, clientIP string) (IssuedSession, PublicUser, error) {
	// Attempt budgets run BEFORE any KDF work.
	ipKey := loginKey("ip", clientIP)
	if ok, wait := s.ipLimiter.allow(ipKey); !ok {
		return IssuedSession{}, PublicUser{}, &RateLimitedError{RetryAfter: wait}
	}
	email := NormalizeEmail(in.Email)
	acctKey := loginKey("acct", email)
	if ok, wait := s.acctLimiter.allow(acctKey); !ok {
		return IssuedSession{}, PublicUser{}, &RateLimitedError{RetryAfter: wait}
	}

	user, err := s.store.FindUserByEmail(ctx, email)
	switch {
	case err == nil:
	case errors.Is(err, ErrNotFound):
		// Unknown email: run the same KDF path against a dummy hash so
		// the attempt is indistinguishable from a wrong password.
		if dh, derr := s.dummyHash(); derr == nil {
			_, _ = s.hasher.VerifyPassword(ctx, in.Password, dh)
		}
		return IssuedSession{}, PublicUser{}, ErrBadCredentials
	default:
		return IssuedSession{}, PublicUser{}, err
	}

	ok, err := s.hasher.VerifyPassword(ctx, in.Password, user.PasswordHash)
	if err != nil {
		return IssuedSession{}, PublicUser{}, err
	}
	if !ok || user.Status != UserStatusActive {
		return IssuedSession{}, PublicUser{}, ErrBadCredentials
	}
	iss, err := s.CreateSession(ctx, user.ID, "")
	if err != nil {
		return IssuedSession{}, PublicUser{}, err
	}
	return iss, publicUser(user), nil
}
