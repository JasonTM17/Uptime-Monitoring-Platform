//go:build integration

package monitor_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/auth"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/config"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/monitor"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// monFixture wires the full real stack: disposable-DB repositories +
// production-shaped services + CSRF + both muxes on one server.
type monFixture struct {
	t      *testing.T
	svc    *auth.Service
	repo   *auth.Repository
	mon    *monitor.Repository
	pool   *pgxpool.Pool
	server *httptest.Server
	origin string
	emails []string
}

func newMonFixture(t *testing.T) *monFixture {
	t.Helper()
	pool := testPool(t)
	repo := auth.NewRepository(pool, 15*time.Second)
	svc := auth.NewService(repo, auth.NewHasher(config.AuthConfig{
		ArgonMemoryKiB: 19 * 1024, ArgonTime: 2, ArgonParallelism: 1,
		ArgonSaltLen: 16, ArgonKeyLen: 32, HashWorkers: 4,
	}), intCfg(), 10)
	f := &monFixture{t: t, svc: svc, repo: repo, pool: pool, origin: "http://monfixture.local"}
	csrf := auth.NewCSRFManager([]byte("mon-fixture-csrf-key-32bytes!"),
		15*time.Minute, false, []string{f.origin})
	authH := auth.NewHandler(svc, auth.HandlerConfig{
		MaxJSONBody: 32 << 10, CSRF: csrf})
	f.mon = monitor.NewRepository(pool, 15*time.Second)
	if err := f.mon.EnsureQuotaBudget(context.Background(), 1000); err != nil {
		t.Fatalf("quota ensure: %v", err)
	}
	monSvc := monitor.NewService(f.mon, f.mon,
		monitor.Caps{RetainedOwner: 1000, RetainedGlobal: 10000})
	monH := monitor.NewHandler(monSvc, svc, monitor.HandlerConfig{
		MaxJSONBody: 32 << 10, CSRF: csrf})
	root := http.NewServeMux()
	root.Handle("/auth/", authH.Mux())
	root.Handle("/monitors", monH.Mux())
	root.Handle("/monitors/", monH.Mux())
	f.server = httptest.NewServer(root)
	t.Cleanup(f.server.Close)
	return f
}

func intCfg() config.AuthConfig {
	return config.AuthConfig{
		SessionAbsoluteExpiry:      7 * 24 * time.Hour,
		SessionIdleExpiry:          24 * time.Hour,
		LoginIPAttemptsPerMin:      5,
		LoginAccountAttemptsPer15M: 5,
		RegisterIPAttemptsPerMin:   1000,
		LimiterMaxKeys:             1000,
	}
}

func (f *monFixture) email(tag string) string {
	e := fmt.Sprintf("%s-%d@monfix.test", tag, time.Now().UnixNano())
	f.emails = append(f.emails, e)
	return e
}

func (f *monFixture) cleanup() {
	ctx := context.Background()
	for _, e := range f.emails {
		_, _ = f.pool.Exec(ctx,
			`DELETE FROM uptime.monitors WHERE user_id IN
			 (SELECT id FROM uptime.users WHERE email=$1)`, e)
		_, _ = f.pool.Exec(ctx,
			`DELETE FROM uptime.sessions WHERE user_id IN
			 (SELECT id FROM uptime.users WHERE email=$1)`, e)
		_, _ = f.pool.Exec(ctx,
			`DELETE FROM uptime.users WHERE email=$1`, e)
	}
}

type monClient struct {
	t       *testing.T
	srv     *httptest.Server
	origin  string
	csrfTok string
	csrfCk  *http.Cookie
	sessCk  *http.Cookie
}

func (f *monFixture) newClient() *monClient {
	return &monClient{t: f.t, srv: f.server, origin: f.origin}
}

func (c *monClient) do(method, path, body string, withCSRF bool) *httptest.ResponseRecorder {
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
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b := new(bytes.Buffer)
	_, _ = b.ReadFrom(resp.Body)
	rec := httptest.NewRecorder()
	rec.Code = resp.StatusCode
	rec.Body = b
	rec.HeaderMap = resp.Header
	return rec
}

const monPW = "fixture-pw-12345678"

func (c *monClient) challenge() {
	rec := c.do(http.MethodGet, "/auth/csrf", "", false)
	if rec.Code != http.StatusOK {
		c.t.Fatalf("challenge %d", rec.Code)
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
		c.t.Fatalf("bad challenge %s", rec.Body.String())
	}
	c.csrfTok = env.Data.Token
}

func (c *monClient) join(email string) {
	c.challenge()
	b, _ := json.Marshal(map[string]string{"email": email, "password": monPW})
	if rec := c.do(http.MethodPost, "/auth/register", string(b), true); rec.Code != http.StatusCreated {
		c.t.Fatalf("register %d %s", rec.Code, rec.Body.String())
	}
	rec := c.do(http.MethodPost, "/auth/login", string(b), true)
	if rec.Code != http.StatusOK {
		c.t.Fatalf("login %d", rec.Code)
	}
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == "uptime_session" {
			c.sessCk = ck
		}
	}
}

func (c *monClient) create(name string) map[string]any {
	body, _ := json.Marshal(map[string]any{
		"name": name, "target_url": "https://example.com/health",
		"interval_seconds": 60, "timeout_seconds": 5})
	rec := c.do(http.MethodPost, "/monitors", string(body), true)
	if rec.Code != http.StatusCreated {
		c.t.Fatalf("create %d %s", rec.Code, rec.Body.String())
	}
	var env struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		c.t.Fatalf("decode: %v", err)
	}
	return env.Data
}

func TestMonitorMutations(t *testing.T) {
	f := newMonFixture(t)
	defer f.cleanup()
	emailA, emailB := f.email("mon-a"), f.email("mon-b")
	a, b := f.newClient(), f.newClient()
	a.join(emailA)
	b.join(emailB)
	ctx := context.Background()

	var created map[string]any
	t.Run("create 201 + Location + owned DTO", func(t *testing.T) {
		created = a.create("api")
		if created["id"] == "" || created["health"] != "UNKNOWN" ||
			created["generation"].(float64) != 1 {
			t.Fatalf("bad create %+v", created)
		}
	})

	t.Run("owner get 200, foreign get 404", func(t *testing.T) {
		id := created["id"].(string)
		if rec := a.do(http.MethodGet, "/monitors/"+id, "", false); rec.Code != http.StatusOK {
			t.Fatalf("owner get %d", rec.Code)
		}
		if rec := b.do(http.MethodGet, "/monitors/"+id, "", false); rec.Code != http.StatusNotFound {
			t.Fatalf("foreign get %d", rec.Code)
		}
	})

	t.Run("patch 200 bumps generation, stale 409", func(t *testing.T) {
		id := created["id"].(string)
		body := `{"expected_generation":1,"name":"api-renamed"}`
		if rec := a.do(http.MethodPatch, "/monitors/"+id, body, true); rec.Code != http.StatusOK {
			t.Fatalf("patch %d %s", rec.Code, rec.Body.String())
		}
		if rec := a.do(http.MethodPatch, "/monitors/"+id, body, true); rec.Code != http.StatusConflict {
			t.Fatalf("stale patch %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("mutation without CSRF -> 403", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"name": "x", "target_url": "https://example.com",
			"interval_seconds": 60, "timeout_seconds": 5})
		if rec := a.do(http.MethodPost, "/monitors", string(body), false); rec.Code != http.StatusForbidden {
			t.Fatalf("csrf-less create %d", rec.Code)
		}
	})

	t.Run("owner cap -> 409 QUOTA_EXCEEDED owner scope", func(t *testing.T) {
		ua, err := f.repo.FindUserByEmail(ctx, emailA)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.pool.Exec(ctx,
			`UPDATE uptime.users SET monitor_limit=1 WHERE id=$1`, ua.ID); err != nil {
			t.Fatal(err)
		}
		defer f.pool.Exec(ctx, `UPDATE uptime.users SET monitor_limit=100 WHERE id=$1`, ua.ID)
		body, _ := json.Marshal(map[string]any{
			"name": "over", "target_url": "https://example.com",
			"interval_seconds": 60, "timeout_seconds": 5})
		rec := a.do(http.MethodPost, "/monitors", string(body), true)
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "QUOTA_EXCEEDED") ||
			!strings.Contains(rec.Body.String(), "owner_monitor_limit") {
			t.Fatalf("quota %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("delete 204, then get/re-delete are 404", func(t *testing.T) {
		id := created["id"].(string)
		body := `{"expected_generation":2}`
		if rec := a.do(http.MethodDelete, "/monitors/"+id, body, true); rec.Code != http.StatusNoContent {
			t.Fatalf("delete %d %s", rec.Code, rec.Body.String())
		}
		if rec := a.do(http.MethodGet, "/monitors/"+id, "", false); rec.Code != http.StatusNotFound {
			t.Fatalf("post-delete get %d", rec.Code)
		}
		if rec := a.do(http.MethodDelete, "/monitors/"+id, body, true); rec.Code != http.StatusNotFound {
			t.Fatalf("re-delete %d", rec.Code)
		}
	})
}

func TestConcurrentPatch(t *testing.T) {
	f := newMonFixture(t)
	defer f.cleanup()
	a := f.newClient()
	a.join(f.email("race"))
	m := a.create("race-target")
	id := m["id"].(string)
	gen := int(m["generation"].(float64))

	const racers = 4
	start := make(chan struct{})
	var wg sync.WaitGroup
	codes := make([]int, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			body := fmt.Sprintf(`{"expected_generation":%d,"name":"w%d"}`, gen, i)
			codes[i] = a.do(http.MethodPatch, "/monitors/"+id, body, true).Code
		}(i)
	}
	close(start)
	wg.Wait()
	wins, conflicts := 0, 0
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			wins++
		case http.StatusConflict:
			conflicts++
		}
	}
	if wins != 1 || wins+conflicts != racers {
		t.Fatalf("codes %v — want exactly one winner, rest 409", codes)
	}
	// The losing writes must not have landed: only one name wins.
	rec := a.do(http.MethodGet, "/monitors/"+id, "", false)
	var env struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Data["generation"].(float64) != float64(gen+1) {
		t.Fatalf("generation=%v, want exactly one bump", env.Data["generation"])
	}
}

func TestActorDisabledBeforeMutation(t *testing.T) {
	f := newMonFixture(t)
	defer f.cleanup()
	email := f.email("dis")
	a := f.newClient()
	a.join(email)
	m := a.create("victim")
	id := m["id"].(string)
	ctx := context.Background()

	u, err := f.repo.FindUserByEmail(ctx, email)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx,
		`UPDATE uptime.users SET status='DISABLED', disabled_at=now() WHERE id=$1`, u.ID); err != nil {
		t.Fatal(err)
	}

	// The session was issued while active — a disabled actor must be
	// rejected at request/mutation time, not slip through on the
	// captured principal.
	body := `{"expected_generation":1,"name":"post-disable"}`
	if rec := a.do(http.MethodPatch, "/monitors/"+id, body, true); rec.Code != http.StatusUnauthorized {
		t.Fatalf("disabled patch %d %s", rec.Code, rec.Body.String())
	}
	body2, _ := json.Marshal(map[string]any{
		"name": "post-disable-create", "target_url": "https://example.com",
		"interval_seconds": 60, "timeout_seconds": 5})
	if rec := a.do(http.MethodPost, "/monitors", string(body2), true); rec.Code != http.StatusUnauthorized {
		t.Fatalf("disabled create %d", rec.Code)
	}
	// The stored row must be untouched — read it via the repository.
	got, err := f.mon.GetMonitor(ctx, u.ID, mustUUID(t, id))
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "victim" || got.Generation != 1 {
		t.Fatalf("disabled actor mutated row %+v", got)
	}
}

func mustUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestPauseResume(t *testing.T) {
	f := newMonFixture(t)
	defer f.cleanup()
	a := f.newClient()
	a.join(f.email("lc"))
	m := a.create("lc-target")
	id := m["id"].(string)

	t.Run("pause 200 preserves health, bumps generation", func(t *testing.T) {
		rec := a.do(http.MethodPost, "/monitors/"+id+"/pause",
			`{"expected_generation":1}`, true)
		if rec.Code != http.StatusOK {
			t.Fatalf("pause %d %s", rec.Code, rec.Body.String())
		}
		var env struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatal(err)
		}
		if env.Data["is_paused"] != true || env.Data["health"] != "UNKNOWN" ||
			env.Data["generation"].(float64) != 2 {
			t.Fatalf("pause state %+v", env.Data)
		}
	})

	t.Run("repeated pause with current gen is idempotent 200", func(t *testing.T) {
		rec := a.do(http.MethodPost, "/monitors/"+id+"/pause",
			`{"expected_generation":2}`, true)
		if rec.Code != http.StatusOK {
			t.Fatalf("re-pause %d", rec.Code)
		}
		var env struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatal(err)
		}
		if env.Data["generation"].(float64) != 2 {
			t.Fatalf("re-pause bumped generation to %v", env.Data["generation"])
		}
	})

	t.Run("resume marks eligibility without fabricating sample", func(t *testing.T) {
		rec := a.do(http.MethodPost, "/monitors/"+id+"/resume",
			`{"expected_generation":2}`, true)
		if rec.Code != http.StatusOK {
			t.Fatalf("resume %d %s", rec.Code, rec.Body.String())
		}
		var env struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatal(err)
		}
		d := env.Data
		if d["is_paused"] != false || d["health"] != "UNKNOWN" ||
			d["last_checked_at"] != nil || d["last_response_time_ms"] != nil {
			t.Fatalf("resume fabricated %+v", d)
		}
		if d["generation"].(float64) != 3 {
			t.Fatalf("resume generation %v", d["generation"])
		}
	})

	t.Run("stale generation 409 on lifecycle", func(t *testing.T) {
		rec := a.do(http.MethodPost, "/monitors/"+id+"/pause",
			`{"expected_generation":1}`, true)
		if rec.Code != http.StatusConflict {
			t.Fatalf("stale pause %d", rec.Code)
		}
	})

	t.Run("foreign pause reads as 404", func(t *testing.T) {
		b := f.newClient()
		b.join(f.email("lc-b"))
		rec := b.do(http.MethodPost, "/monitors/"+id+"/pause",
			`{"expected_generation":3}`, true)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("foreign pause %d", rec.Code)
		}
	})
}

func TestConcurrentLifecycle(t *testing.T) {
	f := newMonFixture(t)
	defer f.cleanup()
	a := f.newClient()
	a.join(f.email("lcc"))
	m := a.create("lcc-target")
	id := m["id"].(string)

	// pause-vs-edit on the same generation must serialize: exactly one
	// winner commits generation 2, losers get 409.
	const racers = 4
	start := make(chan struct{})
	var wg sync.WaitGroup
	codes := make([]int, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			if i%2 == 0 {
				codes[i] = a.do(http.MethodPost, "/monitors/"+id+"/pause",
					`{"expected_generation":1}`, true).Code
			} else {
				codes[i] = a.do(http.MethodPatch, "/monitors/"+id,
					fmt.Sprintf(`{"expected_generation":1,"name":"e%d"}`, i), true).Code
			}
		}(i)
	}
	close(start)
	wg.Wait()
	wins := 0
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			wins++
		case http.StatusConflict:
		default:
			t.Fatalf("unexpected code %d in %v", c, codes)
		}
	}
	if wins != 1 {
		t.Fatalf("codes %v — want exactly one winner", codes)
	}
}
