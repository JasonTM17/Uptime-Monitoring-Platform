//go:build integration

// Behavioral identity tests: real HTTP flow (httptest server + real mux
// + real service + real PostgreSQL on the disposable test database).
// Fixture emails are unique per run and cleaned up afterwards — no
// TRUNCATE of unrelated rows, no sleep-based oracles (channels are the
// concurrency barriers).

package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/auth"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/config"
)

// fixture builds the full real stack once per test: disposable-DB
// repository + production-param hasher (floor params for speed) +
// service + CSRF manager + mux + httptest server.
type fixture struct {
	t      *testing.T
	svc    *auth.Service
	repo   *auth.Repository
	server *httptest.Server
	origin string
	emails []string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	repo := auth.NewRepository(testPool(t), 15*time.Second)
	svc := auth.NewService(repo, auth.NewHasher(config.AuthConfig{
		ArgonMemoryKiB: 19 * 1024, ArgonTime: 2, ArgonParallelism: 1,
		ArgonSaltLen: 16, ArgonKeyLen: 32, HashWorkers: 2,
	}), intCfg())
	csrf := auth.NewCSRFManager([]byte("integration-csrf-key-32bytes!"),
		15*time.Minute, false, nil) // origin list set below
	f := &fixture{t: t, svc: svc, repo: repo, origin: "http://fixture.local"}
	// Rebuild with the fixture origin.
	csrf = auth.NewCSRFManager([]byte("integration-csrf-key-32bytes!"),
		15*time.Minute, false, []string{f.origin})
	h := auth.NewHandler(svc, auth.HandlerConfig{
		MaxJSONBody: 32 << 10, CSRF: csrf,
	})
	f.server = httptest.NewServer(h.Mux())
	t.Cleanup(f.server.Close)
	return f
}

// email returns a unique-per-run canonical email.
func (f *fixture) email(tag string) string {
	e := fmt.Sprintf("%s-%d@fixture.test", tag, time.Now().UnixNano())
	f.emails = append(f.emails, e)
	return e
}

// cleanup removes only rows this fixture created (by email list) —
// disposable DB is shared, so no blanket truncate.
func (f *fixture) cleanup() {
	conn := connect(f.t)
	defer conn.Close(context.Background())
	for _, e := range f.emails {
		_, _ = conn.Exec(context.Background(),
			`DELETE FROM uptime.sessions WHERE user_id IN (SELECT id FROM uptime.users WHERE email=$1)`, e)
		_, _ = conn.Exec(context.Background(), `DELETE FROM uptime.users WHERE email=$1`, e)
	}
}

// client is a minimal cookie-aware HTTP client for the fixture.
type client struct {
	t       *testing.T
	srv     *httptest.Server
	origin  string
	csrfTok string
	csrfCk  *http.Cookie
	sessCk  *http.Cookie
}

func (f *fixture) newClient() *client { return &client{t: f.t, srv: f.server, origin: f.origin} }

func (c *client) do(method, path, body string, withCSRF bool) *httptest.ResponseRecorder {
	req, err := http.NewRequest(method, c.srv.URL+path, strings.NewReader(body))
	if err != nil {
		c.t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if withCSRF {
		req.Header.Set("Origin", c.origin)
		if c.csrfCk != nil {
			req.AddCookie(c.csrfCk)
		}
		if c.csrfTok != "" {
			req.Header.Set("X-CSRF-Token", c.csrfTok)
		}
	}
	if c.sessCk != nil {
		req.AddCookie(c.sessCk)
	}
	// Route through the real server via http.Client so cookies/headers
	// behave like the wire, not like in-process calls.
	rec := httptest.NewRecorder()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b := new(bytes.Buffer)
	_, _ = b.ReadFrom(resp.Body)
	rec.Code = resp.StatusCode
	rec.Body = b
	rec.HeaderMap = resp.Header
	return rec
}

func (c *client) challenge() {
	rec := c.do(http.MethodGet, "/auth/csrf", "", false)
	if rec.Code != http.StatusOK {
		c.t.Fatalf("challenge status %d", rec.Code)
	}
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == "uptime_csrf" {
			c.csrfCk = ck
		}
	}
	var env struct {
		Data struct {
			Token string `json:"csrf_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil || env.Data.Token == "" {
		c.t.Fatalf("bad challenge body: %v", rec.Body.String())
	}
	c.csrfTok = env.Data.Token
}

func (c *client) register(email string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(map[string]string{"email": email, "password": validPW})
	return c.do(http.MethodPost, "/auth/register", string(b), true)
}

func (c *client) login(email string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(map[string]string{"email": email, "password": validPW})
	rec := c.do(http.MethodPost, "/auth/login", string(b), true)
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == "uptime_session" {
			c.sessCk = ck
		}
	}
	return rec
}

func TestAuthFlow(t *testing.T) {
	f := newFixture(t)
	defer f.cleanup()
	email := f.email("flow")
	c := f.newClient()

	t.Run("full flow: challenge -> register -> login -> me -> sessions -> logout", func(t *testing.T) {
		c.challenge()
		if rec := c.register(email); rec.Code != http.StatusCreated {
			b, _ := httputil.DumpResponse(rec.Result(), true)
			t.Fatalf("register %d %s", rec.Code, b)
		}
		rec := c.login(email)
		if rec.Code != http.StatusOK || c.sessCk == nil {
			t.Fatalf("login %d", rec.Code)
		}
		me := c.do(http.MethodGet, "/auth/me", "", false)
		if me.Code != http.StatusOK || !strings.Contains(me.Body.String(), email) {
			t.Fatalf("me %d %s", me.Code, me.Body.String())
		}
		if strings.Contains(me.Body.String(), "password_hash") {
			t.Fatal("me leaks password_hash")
		}
		list := c.do(http.MethodGet, "/auth/sessions", "", false)
		if list.Code != http.StatusOK || strings.Contains(list.Body.String(), "token_hash") {
			t.Fatalf("sessions %d %s", list.Code, list.Body.String())
		}
		out := c.do(http.MethodPost, "/auth/logout", "", true)
		if out.Code != http.StatusOK {
			t.Fatalf("logout %d", out.Code)
		}
		// Post-logout the session must be dead server-side.
		if me := c.do(http.MethodGet, "/auth/me", "", false); me.Code != http.StatusUnauthorized {
			t.Fatalf("post-logout me %d", me.Code)
		}
	})
}

func TestIdentityIsolation(t *testing.T) {
	f := newFixture(t)
	defer f.cleanup()
	emailA, emailB := f.email("iso-a"), f.email("iso-b")
	a, b := f.newClient(), f.newClient()
	a.challenge()
	a.register(emailA)
	a.login(emailA)
	b.challenge()
	b.register(emailB)
	b.login(emailB)
	ctx := context.Background()

	t.Run("session A cannot read as B and vice versa", func(t *testing.T) {
		meA := a.do(http.MethodGet, "/auth/me", "", false)
		if !strings.Contains(meA.Body.String(), emailA) || strings.Contains(meA.Body.String(), emailB) {
			t.Fatal("A session sees wrong identity")
		}
		meB := b.do(http.MethodGet, "/auth/me", "", false)
		if strings.Contains(meB.Body.String(), emailA) || !strings.Contains(meB.Body.String(), emailB) {
			t.Fatal("B session sees wrong identity")
		}
	})

	t.Run("A cannot revoke B's session (foreign -> 404)", func(t *testing.T) {
		ub, _ := f.repo.FindUserByEmail(ctx, emailB)
		bSess, _ := f.svc.ListOwnSessions(ctx, ub.ID, 10, 0)
		if len(bSess) == 0 {
			t.Fatal("B has no sessions")
		}
		// A's client calls DELETE on B's session id.
		rec := a.do(http.MethodDelete, "/auth/sessions/"+bSess[0].ID.String(), "", true)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("foreign revoke %d", rec.Code)
		}
		// B's session still alive.
		if me := b.do(http.MethodGet, "/auth/me", "", false); me.Code != http.StatusOK {
			t.Fatal("foreign revoke killed B's session")
		}
	})

	t.Run("session inventories are disjoint", func(t *testing.T) {
		la := a.do(http.MethodGet, "/auth/sessions", "", false)
		lb := b.do(http.MethodGet, "/auth/sessions", "", false)
		if bytes.Equal(la.Body.Bytes(), lb.Body.Bytes()) {
			t.Fatal("identical inventories across owners")
		}
	})

	t.Run("revoked A session cannot be replayed", func(t *testing.T) {
		if rec := a.do(http.MethodPost, "/auth/logout", "", true); rec.Code != http.StatusOK {
			t.Fatal(rec.Code)
		}
		if me := a.do(http.MethodGet, "/auth/me", "", false); me.Code != http.StatusUnauthorized {
			t.Fatalf("revoked session replay: %d", me.Code)
		}
		// B unaffected.
		if me := b.do(http.MethodGet, "/auth/me", "", false); me.Code != http.StatusOK {
			t.Fatal("A's logout affected B")
		}
	})

	t.Run("concurrent same-email registration yields one account (barrier)", func(t *testing.T) {
		dup := f.email("iso-dup")
		const n = 4
		var wg sync.WaitGroup
		codes := make([]int, n)
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				cc := f.newClient()
				cc.challenge()
				<-start
				// A saturated hash gate answers 429 — bounded
				// backpressure, not a verdict; retry past it.
				for try := 0; try < 8; try++ {
					codes[i] = cc.register(dup).Code
					if codes[i] != http.StatusTooManyRequests {
						break
					}
					time.Sleep(30 * time.Millisecond)
				}
			}(i)
		}
		close(start) // barrier: all racers release together
		wg.Wait()
		var created int
		for _, cd := range codes {
			if cd == http.StatusCreated {
				created++
			}
		}
		if created != 1 {
			t.Fatalf("concurrent register created %d accounts (codes %v)", created, codes)
		}
	})
}
