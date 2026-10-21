package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

// dummyHash returns a lazily-generated PHC so unknown-email attempts
// still execute a real Argon2id verification (uniform KDF path). Only
// SUCCESS is cached: latching a transient failure (e.g. a busy gate on
// the first-ever attempt) would permanently skip the KDF path and
// become a measurable timing oracle.
func (s *Service) dummyHash() (string, error) {
	s.dummyMu.Lock()
	defer s.dummyMu.Unlock()
	if s.dummy != "" {
		return s.dummy, nil
	}
	h, err := s.hasher.HashPassword(context.Background(),
		"dummy-password-for-unknown-users")
	if err != nil {
		return "", err // not cached — retry next attempt
	}
	s.dummy = h
	return s.dummy, nil
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
	// The account bucket is a SOFT deny: a saturated bucket still runs
	// the full auth path, and a VALID credential proves the caller is
	// the owner — so a third party spamming failures can never
	// pin-lock the real user out of their own account. The IP bucket
	// above remains the hard pre-KDF bound on the attacker's volume.
	acctOK, acctWait := s.acctLimiter.allow(acctKey)
	// An over-cap password can never match an account: reject uniformly
	// BEFORE the lookup so known/unknown emails take the same path
	// (otherwise ErrPasswordTooLong 500s only for registered emails —
	// an account-existence oracle).
	if len(in.Password) > maxPasswordBytes {
		return IssuedSession{}, PublicUser{}, ErrBadCredentials
	}

	user, err := s.store.FindUserByEmail(ctx, email)
	switch {
	case err == nil:
	case errors.Is(err, ErrNotFound):
		// Unknown email: run the same KDF path against a dummy hash so
		// the attempt is indistinguishable from a wrong password —
		// INCLUDING error shape: a saturated hash gate must yield the
		// same 429 here as it does on the known-email path below, else
		// busy-window responses become an account-existence oracle.
		if dh, derr := s.dummyHash(); derr == nil {
			if _, verr := s.hasher.VerifyPassword(ctx, in.Password, dh); verr != nil {
				return IssuedSession{}, PublicUser{}, verr
			}
		}
		if !acctOK { // no owner exists to release the lock
			return IssuedSession{}, PublicUser{}, &RateLimitedError{RetryAfter: acctWait}
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
		if !acctOK {
			return IssuedSession{}, PublicUser{}, &RateLimitedError{RetryAfter: acctWait}
		}
		return IssuedSession{}, PublicUser{}, ErrBadCredentials
	}
	// Successful auth releases the account budget — otherwise failed
	// attempts by a third party pin-lock the real user for the window.
	s.acctLimiter.reset(acctKey)
	iss, err := s.CreateSession(ctx, user.ID, "")
	if err != nil {
		return IssuedSession{}, PublicUser{}, err
	}
	return iss, publicUser(user), nil
}
