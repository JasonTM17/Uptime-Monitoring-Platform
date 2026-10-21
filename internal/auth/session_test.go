package auth

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// fakeSessions is an in-memory SessionStore honoring the same contract:
// hash-keyed lookup, owner status/version join via findUser (wired to
// the fake store's single directory), touch, revoke.
type fakeSessions struct {
	mu       sync.Mutex
	findUser func(uuid.UUID) (User, error)
	byHash   map[string]Session
	touchN   int
}

func newFakeSessions() *fakeSessions {
	return &fakeSessions{byHash: map[string]Session{}}
}

func (f *fakeSessions) CreateSession(_ context.Context, userID uuid.UUID, hash []byte,
	exp, idle time.Time, label string) (Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, err := f.findUser(userID)
	if err != nil {
		return Session{}, err
	}
	if u.Status != UserStatusActive {
		return Session{}, ErrInvalidSession
	}
	s := Session{ID: uuid.New(), UserID: userID, SecurityVersion: u.SecurityVersion,
		CreatedAt: time.Now(), LastSeenAt: time.Now(),
		ExpiresAt: exp, IdleExpiresAt: idle, DeviceLabel: label}
	f.byHash[string(hash)] = s
	return s, nil
}

func (f *fakeSessions) FindSessionByTokenHash(_ context.Context, hash []byte) (Session, User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.byHash[string(hash)]
	if !ok {
		return Session{}, User{}, ErrNotFound
	}
	u, err := f.findUser(s.UserID)
	if err != nil {
		return Session{}, User{}, err
	}
	return s, u, nil
}

func (f *fakeSessions) TouchSession(_ context.Context, id uuid.UUID, seen, idle time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.touchN++
	for k, s := range f.byHash {
		if s.ID == id {
			s.LastSeenAt, s.IdleExpiresAt = seen, idle
			f.byHash[k] = s
			return nil
		}
	}
	return ErrNotFound
}
func (f *fakeSessions) RevokeSession(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, s := range f.byHash {
		if s.ID == id {
			now := time.Now()
			s.RevokedAt = &now
			f.byHash[k] = s
			return nil
		}
	}
	return ErrNotFound
}
func (f *fakeSessions) ListSessionsByUser(_ context.Context, userID uuid.UUID, limit, offset int) ([]Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Session
	for _, s := range f.byHash {
		if s.UserID == userID && s.RevokedAt == nil {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID.String() < out[j].ID.String()
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	if offset >= len(out) {
		return nil, nil
	}
	out = out[offset:]
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
func (f *fakeSessions) RevokeSessionForUser(_ context.Context, userID, sessionID uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, s := range f.byHash {
		if s.ID == sessionID && s.UserID == userID {
			if s.RevokedAt != nil {
				return ErrNotFound
			}
			now := time.Now()
			s.RevokedAt = &now
			f.byHash[k] = s
			return nil
		}
	}
	return ErrNotFound
}
func (f *fakeSessions) WithUserLock(_ context.Context, userID uuid.UUID, fn func(tx pgx.Tx, u User) error) error {
	u, err := f.findUser(userID)
	if err != nil {
		return err
	}
	return fn(nil, u)
}
func (f *fakeSessions) touches() int { f.mu.Lock(); defer f.mu.Unlock(); return f.touchN }

func TestSessionToken(t *testing.T) {
	t.Run("token shape and hash", func(t *testing.T) {
		tok, err := newSessionToken()
		if err != nil {
			t.Fatal(err)
		}
		if len(tok) != 43 { // 32 bytes base64url, no padding
			t.Fatalf("token len %d", len(tok))
		}
		h, err := HashToken(tok)
		if err != nil || len(h) != 32 {
			t.Fatalf("hash: %v len=%d", err, len(h))
		}
		// Plaintext never equals its stored form.
		if string(h) == tok {
			t.Fatal("stored hash equals plaintext token")
		}
	})
	t.Run("tokens are unique", func(t *testing.T) {
		a, _ := newSessionToken()
		b, _ := newSessionToken()
		if a == b {
			t.Fatal("duplicate session tokens")
		}
	})
	t.Run("malformed tokens rejected", func(t *testing.T) {
		for _, tok := range []string{"", "short", "!!!!", "AAAA"} {
			if _, err := HashToken(tok); !errors.Is(err, ErrInvalidSession) {
				t.Fatalf("token %q: expected ErrInvalidSession, got %v", tok, err)
			}
		}
	})
	t.Run("entropy failure fails closed", func(t *testing.T) {
		old := randSource
		randSource = strings.NewReader("") // EOF immediately
		defer func() { randSource = old }()
		if _, err := newSessionToken(); !errors.Is(err, errNoEntropy) {
			t.Fatalf("expected errNoEntropy, got %v", err)
		}
	})
}

func sessionSvc(t *testing.T) (*Service, *userSessionStore, User) {
	t.Helper()
	store := newUserSessionStore()
	svc := NewService(store, &countingHasher{}, testCfg())
	u, err := store.CreateUser(context.Background(), "s@x.co", "$h", "")
	if err != nil {
		t.Fatal(err)
	}
	store.putUser(u)
	return svc, store, u
}

func TestSessionLifecycle(t *testing.T) {
	ctx := context.Background()

	t.Run("create and lookup valid", func(t *testing.T) {
		svc, _, u := sessionSvc(t)
		iss, err := svc.CreateSession(ctx, u.ID, "laptop")
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		s, err := svc.LookupSession(ctx, iss.Token)
		if err != nil || s.ID != iss.Session.ID {
			t.Fatalf("lookup: %v %+v", err, s)
		}
	})

	t.Run("revoked session rejected", func(t *testing.T) {
		svc, _, u := sessionSvc(t)
		iss, _ := svc.CreateSession(ctx, u.ID, "")
		if err := svc.RevokeSession(ctx, iss.Session.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.LookupSession(ctx, iss.Token); !errors.Is(err, ErrInvalidSession) {
			t.Fatalf("expected ErrInvalidSession, got %v", err)
		}
	})

	t.Run("expired session rejected (fake clock)", func(t *testing.T) {
		svc, _, u := sessionSvc(t)
		iss, _ := svc.CreateSession(ctx, u.ID, "")
		base := time.Now()
		svc.now = func() time.Time { return base.Add(8 * 24 * time.Hour) } // past absolute
		if _, err := svc.LookupSession(ctx, iss.Token); !errors.Is(err, ErrInvalidSession) {
			t.Fatalf("expected ErrInvalidSession, got %v", err)
		}
	})

	t.Run("idle-expired session rejected", func(t *testing.T) {
		svc, _, u := sessionSvc(t)
		iss, _ := svc.CreateSession(ctx, u.ID, "")
		base := time.Now()
		svc.now = func() time.Time { return base.Add(25 * time.Hour) } // past idle, within absolute
		if _, err := svc.LookupSession(ctx, iss.Token); !errors.Is(err, ErrInvalidSession) {
			t.Fatalf("expected ErrInvalidSession, got %v", err)
		}
	})

	t.Run("disabled user invalidates sessions", func(t *testing.T) {
		svc, store, u := sessionSvc(t)
		iss, _ := svc.CreateSession(ctx, u.ID, "")
		u.Status = UserStatusDisabled
		store.putUser(u)
		if _, err := svc.LookupSession(ctx, iss.Token); !errors.Is(err, ErrInvalidSession) {
			t.Fatalf("expected ErrInvalidSession, got %v", err)
		}
	})

	t.Run("security_version bump invalidates old sessions", func(t *testing.T) {
		svc, store, u := sessionSvc(t)
		iss, _ := svc.CreateSession(ctx, u.ID, "")
		u.SecurityVersion++
		store.putUser(u)
		if _, err := svc.LookupSession(ctx, iss.Token); !errors.Is(err, ErrInvalidSession) {
			t.Fatalf("expected ErrInvalidSession, got %v", err)
		}
	})

	t.Run("cannot create session for disabled user", func(t *testing.T) {
		svc, store, u := sessionSvc(t)
		u.Status = UserStatusDisabled
		store.putUser(u)
		if _, err := svc.CreateSession(ctx, u.ID, ""); !errors.Is(err, ErrInvalidSession) {
			t.Fatalf("expected ErrInvalidSession, got %v", err)
		}
	})

	t.Run("last_seen writes coalesce", func(t *testing.T) {
		svc, store, u := sessionSvc(t)
		iss, _ := svc.CreateSession(ctx, u.ID, "")
		before := store.touches()
		// Immediate second lookup: inside the coalesce window.
		if _, err := svc.LookupSession(ctx, iss.Token); err != nil {
			t.Fatal(err)
		}
		if store.touches() != before {
			t.Fatal("touch ran inside the coalesce window")
		}
		// Fake clock past the window: exactly one touch.
		base := time.Now()
		svc.now = func() time.Time { return base.Add(2 * time.Minute) }
		if _, err := svc.LookupSession(ctx, iss.Token); err != nil {
			t.Fatal(err)
		}
		if store.touches() != before+1 {
			t.Fatalf("expected one touch past window, delta=%d", store.touches()-before)
		}
	})

	t.Run("revoke vs lookup race is safe", func(t *testing.T) {
		svc, _, u := sessionSvc(t)
		iss, _ := svc.CreateSession(ctx, u.ID, "")
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(2)
			go func() { defer wg.Done(); _, _ = svc.LookupSession(ctx, iss.Token) }()
			go func() { defer wg.Done(); _ = svc.RevokeSession(ctx, iss.Session.ID) }()
		}
		wg.Wait()
	})
}
