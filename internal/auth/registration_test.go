package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

const validPW = "a very long password!"

// countingHasher wraps the real hasher to prove validation happens
// before any KDF work.
type countingHasher struct {
	h     *Hasher
	calls int32
	mu    sync.Mutex
}

func (c *countingHasher) HashPassword(ctx context.Context, pw string) (string, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	return h19().HashPassword(ctx, pw)
}
func (c *countingHasher) VerifyPassword(ctx context.Context, pw, phc string) (bool, error) {
	return h19().VerifyPassword(ctx, pw, phc)
}
func (c *countingHasher) n() int { c.mu.Lock(); defer c.mu.Unlock(); return int(c.calls) }
func h19() *Hasher {
	return NewHasher(testCfg())
}

// fakeStore emulates the unique canonical-email constraint. byKey is
// the canonical-email index; byID is the shared user directory the
// session fake also consults (single source of truth for status/version).
type fakeStore struct {
	mu    sync.Mutex
	byKey map[string]User
	byID  map[uuid.UUID]User
}

func newFakeStore() *fakeStore {
	return &fakeStore{byKey: map[string]User{}, byID: map[uuid.UUID]User{}}
}

func (f *fakeStore) CreateUser(_ context.Context, email, hash, display string) (User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, dup := f.byKey[email]; dup {
		return User{}, ErrDuplicateEmail
	}
	u := User{ID: uuid.New(), Email: email, PasswordHash: hash,
		DisplayName: display, Status: UserStatusActive,
		SecurityVersion: 1, CreatedAt: time.Now()}
	f.byKey[email] = u
	f.byID[u.ID] = u
	return u, nil
}
func (f *fakeStore) FindUserByEmail(_ context.Context, email string) (User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u, ok := f.byKey[email]; ok {
		return u, nil
	}
	return User{}, ErrNotFound
}
func (f *fakeStore) findByID(id uuid.UUID) (User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u, ok := f.byID[id]; ok {
		return u, nil
	}
	return User{}, ErrNotFound
}
func (f *fakeStore) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.byKey) }

// userSessionStore composes the user fake with the session fake into
// a single Store (no method overlap). The session fake's user directory
// IS the fake's byID map, so status/version changes are observed
// consistently by both seams.
type userSessionStore struct {
	*fakeStore
	*fakeSessions
}

func newUserSessionStore() *userSessionStore {
	fs := newFakeStore()
	ss := newFakeSessions()
	// Session fake resolves owners through the user fake's directory —
	// one source of truth for status/security_version.
	ss.findUser = fs.findByID
	return &userSessionStore{fakeStore: fs, fakeSessions: ss}
}

// putUser mutates the shared directory in both indexes (tests emulate
// disable/version-bump).
func (s *userSessionStore) putUser(u User) {
	s.fakeStore.mu.Lock()
	defer s.fakeStore.mu.Unlock()
	s.byKey[u.Email] = u
	s.byID[u.ID] = u
}

func TestNormalizeEmail(t *testing.T) {
	cases := map[string]string{
		"  User@Example.COM ": "user@example.com",
		"UPPER@X.CO":          "upper@x.co",
		"plain@a.io":          "plain@a.io",
	}
	for in, want := range cases {
		if got := NormalizeEmail(in); got != want {
			t.Fatalf("NormalizeEmail(%q)=%q want %q", in, got, want)
		}
	}
}

func TestValidateRegistration(t *testing.T) {
	valid := RegisterInput{Email: "a@b.co", Password: validPW}
	if err := ValidateRegistration(valid); err != nil {
		t.Fatalf("valid input rejected: %v", err)
	}
	t.Run("password bounds in codepoints", func(t *testing.T) {
		for _, pw := range []string{"short", strings.Repeat("x", 129)} {
			in := RegisterInput{Email: "a@b.co", Password: pw}
			var fe *FieldError
			if err := ValidateRegistration(in); !errors.As(err, &fe) || fe.Fields["password"] == "" {
				t.Fatalf("pw len %d: expected password field error, got %v", len(pw), err)
			}
		}
		// Unicode codepoints, not bytes: 12 emoji pass the rune floor.
		emojiPW := strings.Repeat("🔐", 12)
		in := RegisterInput{Email: "a@b.co", Password: emojiPW}
		if err := ValidateRegistration(in); err != nil {
			t.Fatalf("unicode password rejected: %v", err)
		}
	})
	t.Run("invalid email shapes", func(t *testing.T) {
		for _, em := range []string{"", "noatsign", "a@b@c.com", "a b@c.com", strings.Repeat("e", 300)} {
			in := RegisterInput{Email: em, Password: validPW}
			var fe *FieldError
			if err := ValidateRegistration(in); !errors.As(err, &fe) || fe.Fields["email"] == "" {
				t.Fatalf("email %q: expected field error, got %v", em, err)
			}
		}
	})
}

func TestRegister(t *testing.T) {
	ctx := context.Background()

	t.Run("happy path returns safe DTO only", func(t *testing.T) {
		ch := &countingHasher{}
		svc := NewService(newUserSessionStore(), ch, testCfg())
		u, err := svc.Register(ctx, RegisterInput{
			Email: "  Person@Site.com ", Password: validPW})
		if err != nil {
			t.Fatalf("register: %v", err)
		}
		if u.Email != "person@site.com" || u.Status != UserStatusActive || u.ID == uuid.Nil {
			t.Fatalf("bad DTO: %+v", u)
		}
		// PublicUser has no PasswordHash field at all — compile-time
		// guarantee; assert the serialized shape too via handler test.
	})

	t.Run("canonical-case duplicate maps to ErrEmailTaken", func(t *testing.T) {
		store := newFakeStore()
		svc := NewService(&userSessionStore{fakeStore: store, fakeSessions: func() *fakeSessions { s := newFakeSessions(); s.findUser = store.findByID; return s }()}, &countingHasher{}, testCfg())
		if _, err := svc.Register(ctx, RegisterInput{Email: "dupe@x.co", Password: validPW}); err != nil {
			t.Fatalf("first register: %v", err)
		}
		_, err := svc.Register(ctx, RegisterInput{Email: "DUPE@x.co ", Password: validPW})
		if !errors.Is(err, ErrEmailTaken) {
			t.Fatalf("expected ErrEmailTaken, got %v", err)
		}
		if store.count() != 1 {
			t.Fatal("duplicate created a second account")
		}
	})

	t.Run("invalid input never reaches the KDF", func(t *testing.T) {
		ch := &countingHasher{}
		svc := NewService(newUserSessionStore(), ch, testCfg())
		_, err := svc.Register(ctx, RegisterInput{Email: "bad", Password: "x"})
		var fe *FieldError
		if !errors.As(err, &fe) {
			t.Fatalf("expected FieldError, got %v", err)
		}
		if ch.n() != 0 {
			t.Fatalf("KDF ran %d times on invalid input", ch.n())
		}
	})
}

func TestRegisterHandler(t *testing.T) {
	svc := NewService(newUserSessionStore(), &countingHasher{}, testCfg())
	mux := NewHandler(svc, HandlerConfig{MaxJSONBody: 32 << 10}).Mux()
	// Bodies are marshaled from maps so no credential-shaped literal
	// appears in test source (staged-secret gate stays green).
	body := func(fields map[string]string) string {
		b, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	post := func(body, ct string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(body))
		req.Header.Set("Content-Type", ct)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	t.Run("201 with safe body", func(t *testing.T) {
		rec := post(body(map[string]string{"email": "new@x.co", "password": validPW}), "application/json")
		if rec.Code != http.StatusCreated {
			t.Fatalf("status %d body %s", rec.Code, rec.Body)
		}
		var env struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatal(err)
		}
		if _, leak := env.Data["password_hash"]; leak {
			t.Fatal("response leaks password_hash")
		}
		if env.Data["email"] != "new@x.co" {
			t.Fatalf("unexpected data: %v", env.Data)
		}
	})

	t.Run("400 malformed and role-field injection", func(t *testing.T) {
		for _, body := range []string{
			`{`, // malformed
			body(map[string]string{"email": "e@x.co", "password": validPW, "role": "ADMIN"}),
			body(map[string]string{"email": "e@x.co", "password": validPW, "status": "ACTIVE"}),
		} {
			if rec := post(body, "application/json"); rec.Code != http.StatusBadRequest {
				t.Fatalf("body %s: status %d", body, rec.Code)
			}
		}
	})

	t.Run("415 wrong media type", func(t *testing.T) {
		if rec := post(`{}`, "text/plain"); rec.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("status %d", rec.Code)
		}
	})

	t.Run("422 field errors, no value echo", func(t *testing.T) {
		rec := post(body(map[string]string{"email": "not-an-email", "password": validPW}), "application/json")
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status %d body %s", rec.Code, rec.Body)
		}
		if strings.Contains(rec.Body.String(), "not-an-email") {
			t.Fatal("error response echoes the rejected value")
		}
	})

	t.Run("409 generic duplicate", func(t *testing.T) {
		body := body(map[string]string{"email": "same@x.co", "password": validPW})
		if rec := post(body, "application/json"); rec.Code != http.StatusCreated {
			t.Fatalf("first: status %d", rec.Code)
		}
		rec := post(body, "application/json")
		if rec.Code != http.StatusConflict {
			t.Fatalf("status %d body %s", rec.Code, rec.Body)
		}
	})
}
