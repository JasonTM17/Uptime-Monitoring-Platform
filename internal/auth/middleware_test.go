package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// sessionClient logs a user in and returns the raw token + handler mux.
func sessionClient(t *testing.T, email string) (*Service, *userSessionStore, *http.ServeMux, string) {
	t.Helper()
	store := newUserSessionStore()
	svc := NewService(store, &countingHasher{}, testCfg())
	if _, err := svc.Register(context.Background(), RegisterInput{
		Email: email, Password: validPW}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	u, _ := store.FindUserByEmail(context.Background(), email)
	iss, err := svc.CreateSession(context.Background(), u.ID, "test")
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	mux := NewHandler(svc, HandlerConfig{MaxJSONBody: 32 << 10, CSRF: testCSRF()}).Mux()
	return svc, store, mux, iss.Token
}

func getWithSession(mux *http.ServeMux, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestAuthentication(t *testing.T) {
	_, _, mux, _ := sessionClient(t, "auth@x.co")

	t.Run("missing cookie -> 401", func(t *testing.T) {
		if rec := getWithSession(mux, "/auth/me", ""); rec.Code != http.StatusUnauthorized {
			t.Fatalf("status %d", rec.Code)
		}
	})
	t.Run("malformed token -> 401", func(t *testing.T) {
		if rec := getWithSession(mux, "/auth/me", "not-a-token"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("status %d", rec.Code)
		}
	})
	t.Run("forged-but-unknown token -> 401", func(t *testing.T) {
		forged, _ := newSessionToken()
		if rec := getWithSession(mux, "/auth/me", forged); rec.Code != http.StatusUnauthorized {
			t.Fatalf("status %d", rec.Code)
		}
	})
	t.Run("revoked session -> 401", func(t *testing.T) {
		svc2, _, mux2, tok2 := sessionClient(t, "rv@x.co")
		// find and revoke via service
		sess, err := svc2.LookupSession(context.Background(), tok2)
		if err != nil {
			t.Fatal(err)
		}
		if err := svc2.RevokeSession(context.Background(), sess.ID); err != nil {
			t.Fatal(err)
		}
		if rec := getWithSession(mux2, "/auth/me", tok2); rec.Code != http.StatusUnauthorized {
			t.Fatalf("status %d", rec.Code)
		}
	})
	t.Run("disabled user -> 401", func(t *testing.T) {
		_, store, mux3, tok3 := sessionClient(t, "du@x.co")
		u, _ := store.FindUserByEmail(context.Background(), "du@x.co")
		u.Status = UserStatusDisabled
		store.putUser(u)
		if rec := getWithSession(mux3, "/auth/me", tok3); rec.Code != http.StatusUnauthorized {
			t.Fatalf("status %d", rec.Code)
		}
	})
	t.Run("stale security_version -> 401", func(t *testing.T) {
		_, store, mux4, tok4 := sessionClient(t, "sv@x.co")
		u, _ := store.FindUserByEmail(context.Background(), "sv@x.co")
		u.SecurityVersion++
		store.putUser(u)
		if rec := getWithSession(mux4, "/auth/me", tok4); rec.Code != http.StatusUnauthorized {
			t.Fatalf("status %d", rec.Code)
		}
	})
	t.Run("expired session -> 401", func(t *testing.T) {
		svc5, _, mux5, tok5 := sessionClient(t, "ex@x.co")
		base := time.Now()
		svc5.now = func() time.Time { return base.Add(8 * 24 * time.Hour) }
		if rec := getWithSession(mux5, "/auth/me", tok5); rec.Code != http.StatusUnauthorized {
			t.Fatalf("status %d", rec.Code)
		}
	})
}

func TestMe(t *testing.T) {
	_, _, mux, token := sessionClient(t, "me@x.co")
	rec := getWithSession(mux, "/auth/me", token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body)
	}
	var env struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Data["session_expires_at"] == nil {
		t.Fatal("missing session_expires_at")
	}
	user := env.Data["user"].(map[string]any)
	for _, banned := range []string{"password_hash", "token", "security_version"} {
		if _, leak := user[banned]; leak {
			t.Fatalf("me leaks %s", banned)
		}
	}
	if user["email"] != "me@x.co" {
		t.Fatalf("bad user: %v", user)
	}
}

func TestLogout(t *testing.T) {
	svc, _, mux, token := sessionClient(t, "lo@x.co")
	ck, csrfTok := csrfFlow(t, mux)

	post := func(sessionTok string) *httptest.ResponseRecorder {
		req := authedPost("/auth/logout", "", testOrigin, ck, csrfTok)
		if sessionTok != "" {
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionTok})
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	t.Run("logout revokes server-side and clears cookie", func(t *testing.T) {
		rec := post(token)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		var cleared bool
		for _, c := range rec.Result().Cookies() {
			if c.Name == sessionCookieName && c.MaxAge < 0 {
				cleared = true
			}
		}
		if !cleared {
			t.Fatal("cookie not cleared")
		}
		if _, err := svc.LookupSession(context.Background(), token); !errors.Is(err, ErrInvalidSession) {
			t.Fatalf("session still valid after logout: %v", err)
		}
	})
	t.Run("repeated logout still 200", func(t *testing.T) {
		if rec := post(token); rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
	})
	t.Run("logout without session cookie still 200", func(t *testing.T) {
		if rec := post(""); rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
	})
	t.Run("logout without CSRF -> 403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status %d", rec.Code)
		}
	})
}

func TestActorRecheck(t *testing.T) {
	svc, store, _, token := sessionClient(t, "rc@x.co")
	ctx := context.Background()
	sess, owner, err := svc.authenticateToken(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	p := Principal{User: owner, Session: sess}

	t.Run("fresh actor passes", func(t *testing.T) {
		u, err := svc.RecheckActor(ctx, p)
		if err != nil || u.ID != owner.ID {
			t.Fatalf("recheck: %v", err)
		}
	})
	t.Run("version bump invalidates snapshot", func(t *testing.T) {
		u2 := owner
		u2.SecurityVersion++
		store.putUser(u2)
		if _, err := svc.RecheckActor(ctx, p); !errors.Is(err, ErrInvalidSession) {
			t.Fatalf("expected ErrInvalidSession, got %v", err)
		}
	})
	t.Run("disable invalidates snapshot", func(t *testing.T) {
		u3 := owner
		u3.Status = UserStatusDisabled
		store.putUser(u3)
		if _, err := svc.RecheckActor(ctx, p); !errors.Is(err, ErrInvalidSession) {
			t.Fatalf("expected ErrInvalidSession, got %v", err)
		}
	})
}

func TestOwnSessionRoutes(t *testing.T) {
	svc, _, mux, token := sessionClient(t, "own@x.co")
	ctx := context.Background()
	u, _ := svc.store.FindUserByEmail(ctx, "own@x.co")
	second, _ := svc.CreateSession(ctx, u.ID, "second-device")

	t.Run("list own sessions with current flag", func(t *testing.T) {
		rec := getWithSession(mux, "/auth/sessions", token)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d body %s", rec.Code, rec.Body)
		}
		var env struct {
			Data struct {
				Sessions []sessionDTO `json:"sessions"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatal(err)
		}
		if len(env.Data.Sessions) != 2 {
			t.Fatalf("sessions=%d want 2", len(env.Data.Sessions))
		}
		var currentCount int
		for _, s := range env.Data.Sessions {
			if s.Current {
				currentCount++
			}
		}
		if currentCount != 1 {
			t.Fatalf("current flags=%d", currentCount)
		}
	})

	t.Run("page_size is bounded", func(t *testing.T) {
		rec := getWithSession(mux, "/auth/sessions?page_size=9999", token)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		var env struct {
			Data struct {
				PageSize int `json:"page_size"`
			} `json:"data"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &env)
		if env.Data.PageSize > maxSessionPageSize {
			t.Fatalf("page_size %d not bounded", env.Data.PageSize)
		}
	})

	t.Run("foreign session delete -> 404", func(t *testing.T) {
		_, _, _, otherTok := sessionClient(t, "other@x.co")
		sess, _ := svc.LookupSession(ctx, otherTok)
		ck, csrfTok := csrfFlow(t, mux)
		req := authedPost("/auth/sessions/"+sess.ID.String(), "", testOrigin, ck, csrfTok)
		req.Method = http.MethodDelete
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status %d", rec.Code)
		}
	})

	t.Run("delete own session -> 204 and lookup fails", func(t *testing.T) {
		ck, csrfTok := csrfFlow(t, mux)
		req := authedPost("/auth/sessions/"+second.Session.ID.String(), "", testOrigin, ck, csrfTok)
		req.Method = http.MethodDelete
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status %d", rec.Code)
		}
		if _, err := svc.LookupSession(ctx, second.Token); !errors.Is(err, ErrInvalidSession) {
			t.Fatalf("deleted session still valid: %v", err)
		}
	})

	t.Run("revoke current clears cookie", func(t *testing.T) {
		svc3, _, mux3, tok3 := sessionClient(t, "cur@x.co")
		sess, _ := svc3.LookupSession(ctx, tok3)
		ck, csrfTok := csrfFlow(t, mux3)
		req := authedPost("/auth/sessions/"+sess.ID.String(), "", testOrigin, ck, csrfTok)
		req.Method = http.MethodDelete
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: tok3})
		rec := httptest.NewRecorder()
		mux3.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status %d", rec.Code)
		}
		var cleared bool
		for _, c := range rec.Result().Cookies() {
			if c.Name == sessionCookieName && c.MaxAge < 0 {
				cleared = true
			}
		}
		if !cleared {
			t.Fatal("current-session revoke did not clear cookie")
		}
	})

	t.Run("malformed session id -> 404", func(t *testing.T) {
		ck, csrfTok := csrfFlow(t, mux)
		req := authedPost("/auth/sessions/not-a-uuid", "", testOrigin, ck, csrfTok)
		req.Method = http.MethodDelete
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status %d", rec.Code)
		}
	})

	t.Run("no token/hash leaks in DTOs", func(t *testing.T) {
		rec := getWithSession(mux, "/auth/sessions", token)
		if strings.Contains(rec.Body.String(), "token_hash") ||
			strings.Contains(rec.Body.String(), token) {
			t.Fatal("session inventory leaks token material")
		}
	})
}
