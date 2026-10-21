package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testOrigin = "http://localhost:8080"

func testCSRF() *CSRFManager {
	return NewCSRFManager([]byte("test-csrf-key-32-bytes-padding!!"),
		15*time.Minute, false, []string{testOrigin, "http://127.0.0.1:8080"})
}

// csrfFlow performs the real challenge round-trip against a mux:
// GET /auth/csrf -> readable cookie + body token.
func csrfFlow(t *testing.T, mux http.Handler) (*http.Cookie, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/auth/csrf", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge status %d", rec.Code)
	}
	var ck *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == csrfCookieName {
			ck = c
		}
	}
	if ck == nil {
		t.Fatal("no csrf cookie issued")
	}
	body := rec.Body.String()
	const marker = `"csrf_token":"`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("no csrf_token in body: %s", body)
	}
	token := body[i+len(marker):]
	if j := strings.Index(token, `"`); j >= 0 {
		token = token[:j]
	}
	return ck, token
}

// authedPost builds a mutation request with Origin + CSRF cookie/header.
func authedPost(url, body, origin string, ck *http.Cookie, token string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", origin)
	if ck != nil {
		req.AddCookie(ck)
	}
	if token != "" {
		req.Header.Set(csrfHeader, token)
	}
	return req
}

func TestCSRFToken(t *testing.T) {
	m := testCSRF()

	t.Run("issue-verify roundtrip", func(t *testing.T) {
		rec := httptest.NewRecorder()
		token, err := m.Issue(rec)
		if err != nil || token == "" {
			t.Fatalf("issue: %v", err)
		}
		if err := m.verifyToken(token); err != nil {
			t.Fatalf("verify: %v", err)
		}
	})
	t.Run("tampered signature rejected", func(t *testing.T) {
		rec := httptest.NewRecorder()
		token, _ := m.Issue(rec)
		bad := token[:len(token)-2] + "XX"
		if err := m.verifyToken(bad); err == nil {
			t.Fatal("tampered token accepted")
		}
	})
	t.Run("expired challenge rejected (fake clock)", func(t *testing.T) {
		base := time.Now()
		m.now = func() time.Time { return base }
		rec := httptest.NewRecorder()
		token, _ := m.Issue(rec)
		m.now = func() time.Time { return base.Add(16 * time.Minute) }
		if err := m.verifyToken(token); err == nil {
			t.Fatal("expired token accepted")
		}
	})
	t.Run("wrong key rejected", func(t *testing.T) {
		other := NewCSRFManager([]byte("a-different-key-entirely-32bytes!"),
			15*time.Minute, false, nil)
		rec := httptest.NewRecorder()
		token, _ := m.Issue(rec)
		if err := other.verifyToken(token); err == nil {
			t.Fatal("foreign signature accepted")
		}
	})
}

func TestOriginValidation(t *testing.T) {
	m := testCSRF()
	req := func(origin string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/x", nil)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		return r
	}
	cases := []struct {
		origin string
		ok     bool
	}{
		{testOrigin, true},
		{"http://127.0.0.1:8080", true},
		{"", false},
		{"https://localhost:8080", false},         // scheme mismatch
		{"http://localhost:9090", false},          // port mismatch
		{"http://sub.localhost:8080", false},      // subdomain
		{"http://localhost:8080.evil.com", false}, // suffix attack
		{"http://localhost:8080/path", false},     // path not an origin
		{"null", false},
	}
	for _, c := range cases {
		err := m.ValidateOrigin(req(c.origin))
		if c.ok && err != nil {
			t.Fatalf("origin %q wrongly rejected", c.origin)
		}
		if !c.ok && err == nil {
			t.Fatalf("origin %q wrongly accepted", c.origin)
		}
	}
}

func TestPreAuthChallenge(t *testing.T) {
	m := testCSRF()
	// Full Validate: issue -> cookie+header roundtrip.
	rec := httptest.NewRecorder()
	token, _ := m.Issue(rec)
	ck := &http.Cookie{Name: csrfCookieName, Value: token}

	pass := func(mut func(*http.Request)) error {
		r := authedPost("/auth/login", "{}", testOrigin, ck, token)
		if mut != nil {
			mut(r)
		}
		return m.Validate(r)
	}
	t.Run("valid challenge passes", func(t *testing.T) {
		if err := pass(nil); err != nil {
			t.Fatalf("validate: %v", err)
		}
	})
	t.Run("missing Origin fails", func(t *testing.T) {
		if err := pass(func(r *http.Request) { r.Header.Del("Origin") }); err == nil {
			t.Fatal("accepted missing Origin")
		}
	})
	t.Run("wrong Origin fails", func(t *testing.T) {
		if err := pass(func(r *http.Request) {
			r.Header.Set("Origin", "http://evil.example")
		}); err == nil {
			t.Fatal("accepted foreign origin")
		}
	})
	t.Run("missing header fails", func(t *testing.T) {
		if err := pass(func(r *http.Request) { r.Header.Del(csrfHeader) }); err == nil {
			t.Fatal("accepted missing header")
		}
	})
	t.Run("missing cookie fails", func(t *testing.T) {
		r := authedPost("/auth/login", "{}", testOrigin, nil, token)
		if err := m.Validate(r); err == nil {
			t.Fatal("accepted missing cookie")
		}
	})
	t.Run("header-cookie mismatch fails", func(t *testing.T) {
		rec2 := httptest.NewRecorder()
		other, _ := m.Issue(rec2)
		r := authedPost("/auth/login", "{}", testOrigin, ck, other)
		if err := m.Validate(r); err == nil {
			t.Fatal("accepted mismatched pair")
		}
	})
}

func TestCSRFGatedRoutes(t *testing.T) {
	svc, _ := loginSvc(t)
	h := NewHandler(svc, HandlerConfig{MaxJSONBody: 32 << 10, CSRF: testCSRF()})
	mux := h.Mux()
	bb, _ := json.Marshal(map[string]string{"email": "g@x.co", "password": validPW})
	body := string(bb)

	t.Run("register without challenge -> 403 CSRF_REJECTED", func(t *testing.T) {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/auth/register",
			strings.NewReader(body)))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status %d body %s", rec.Code, rec.Body)
		}
	})

	t.Run("register with challenge -> 201", func(t *testing.T) {
		ck, token := csrfFlow(t, mux)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, authedPost("/auth/register", body, testOrigin, ck, token))
		if rec.Code != http.StatusCreated {
			t.Fatalf("status %d body %s", rec.Code, rec.Body)
		}
	})

	t.Run("challenge is reusable within TTL for login", func(t *testing.T) {
		ck, token := csrfFlow(t, mux)
		// register first
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, authedPost("/auth/register", body, testOrigin, ck, token))
		lb := body
		rec2 := httptest.NewRecorder()
		mux.ServeHTTP(rec2, authedPost("/auth/login", lb, testOrigin, ck, token))
		if rec2.Code != http.StatusOK {
			t.Fatalf("login status %d body %s", rec2.Code, rec2.Body)
		}
	})
}
