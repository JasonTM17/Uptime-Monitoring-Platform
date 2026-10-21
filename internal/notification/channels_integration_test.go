//go:build integration

package notification_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/auth"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/config"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/monitor"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("TEST_DATABASE_URL is required for integration tests (point it at the disposable postgres-test database)")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// chanFixture wires the real stack: disposable-DB repositories +
// production services + CSRF + both channel and monitor muxes.
type chanFixture struct {
	t      *testing.T
	pool   *pgxpool.Pool
	crepo  *notification.Repository
	server *httptest.Server
	origin string
	emails []string
}

func newChanFixture(t *testing.T, caps notification.Caps) *chanFixture {
	t.Helper()
	pool := testPool(t)
	repo := auth.NewRepository(pool, 15*time.Second)
	svc := auth.NewService(repo, auth.NewHasher(config.AuthConfig{
		ArgonMemoryKiB: 19 * 1024, ArgonTime: 2, ArgonParallelism: 1,
		ArgonSaltLen: 16, ArgonKeyLen: 32, HashWorkers: 4,
	}), chanAuthCfg(), 10)
	f := &chanFixture{t: t, pool: pool, origin: "http://chanfixture.local"}
	csrf := auth.NewCSRFManager([]byte("chan-fixture-csrf-key-32byte!"),
		15*time.Minute, false, []string{f.origin})
	authH := auth.NewHandler(svc, auth.HandlerConfig{
		MaxJSONBody: 32 << 10, CSRF: csrf})
	f.crepo = notification.NewRepository(pool, 15*time.Second)
	csvc := notification.NewService(f.crepo, f.crepo, caps)
	chanH := notification.NewHandler(csvc, svc, notification.HandlerConfig{
		MaxJSONBody: 32 << 10, CSRF: csrf})
	mrepo := monitor.NewRepository(pool, 15*time.Second)
	if err := mrepo.EnsureQuotaBudget(context.Background(), 10000); err != nil {
		t.Fatalf("quota ensure: %v", err)
	}
	monH := monitor.NewHandler(
		monitor.NewService(mrepo, mrepo,
			monitor.Caps{RetainedOwner: 1000, RetainedGlobal: 10000}),
		svc, monitor.HandlerConfig{
			MaxJSONBody:        32 << 10,
			CSRF:               csrf,
			ChannelEligibility: notification.EligibleChannelIDs,
		})
	root := http.NewServeMux()
	root.Handle("/auth/", authH.Mux())
	root.Handle("/notification-channels", chanH.Mux())
	root.Handle("/notification-channels/", chanH.Mux())
	root.Handle("/monitors", monH.Mux())
	root.Handle("/monitors/", monH.Mux())
	f.server = httptest.NewServer(root)
	t.Cleanup(f.server.Close)
	return f
}

func chanAuthCfg() config.AuthConfig {
	return config.AuthConfig{
		SessionAbsoluteExpiry:      7 * 24 * time.Hour,
		SessionIdleExpiry:          24 * time.Hour,
		LoginIPAttemptsPerMin:      5,
		LoginAccountAttemptsPer15M: 5,
		RegisterIPAttemptsPerMin:   1000,
		LimiterMaxKeys:             1000,
	}
}

func (f *chanFixture) email(tag string) string {
	e := fmt.Sprintf("%s-%d@chanfix.test", tag, time.Now().UnixNano())
	f.emails = append(f.emails, e)
	return e
}

func (f *chanFixture) cleanup() {
	ctx := context.Background()
	for _, e := range f.emails {
		_, _ = f.pool.Exec(ctx,
			`DELETE FROM uptime.notification_channels WHERE user_id IN
			 (SELECT id FROM uptime.users WHERE email=$1)`, e)
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

// pendingCount returns the global pending counted set — every
// PENDING_VERIFICATION row including tombstoned pending (F03).
func pendingCount(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM uptime.notification_channels
		 WHERE status='PENDING_VERIFICATION'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

type chanClient struct {
	t       *testing.T
	srv     *httptest.Server
	origin  string
	csrfTok string
	csrfCk  *http.Cookie
	sessCk  *http.Cookie
}

func (f *chanFixture) newClient() *chanClient {
	return &chanClient{t: f.t, srv: f.server, origin: f.origin}
}

const chanPW = "fixture-pw-12345678"

func (c *chanClient) do(method, path, body string, withCSRF bool) *httptest.ResponseRecorder {
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

func (c *chanClient) challenge() {
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

func (c *chanClient) join(email string) {
	c.challenge()
	b, _ := json.Marshal(map[string]string{"email": email, "password": chanPW})
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

func dataOf(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var env struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return env.Data
}

func errCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return env.Error.Code
}

func (c *chanClient) createChannel(label string, want int) *httptest.ResponseRecorder {
	c.t.Helper()
	b, _ := json.Marshal(map[string]string{"label": label})
	rec := c.do(http.MethodPost, "/notification-channels", string(b), true)
	if rec.Code != want {
		c.t.Fatalf("create channel %d %s", rec.Code, rec.Body.String())
	}
	return rec
}

func (c *chanClient) channelID(label string) string {
	c.t.Helper()
	return dataOf(c.t, c.createChannel(label, http.StatusCreated))["id"].(string)
}

func (c *chanClient) createMonitor(name string) map[string]any {
	c.t.Helper()
	b, _ := json.Marshal(map[string]any{
		"name": name, "target_url": "https://example.com/health",
		"interval_seconds": 60, "timeout_seconds": 5})
	rec := c.do(http.MethodPost, "/monitors", string(b), true)
	if rec.Code != http.StatusCreated {
		c.t.Fatalf("create monitor %d %s", rec.Code, rec.Body.String())
	}
	return dataOf(c.t, rec)
}

func (c *chanClient) bind(monID string, gen int64, ids []string, want int) *httptest.ResponseRecorder {
	c.t.Helper()
	body, _ := json.Marshal(map[string]any{
		"expected_generation": gen, "channel_ids": ids})
	rec := c.do(http.MethodPut,
		"/monitors/"+monID+"/notification-channels", string(body), true)
	if rec.Code != want {
		c.t.Fatalf("bind %d %s", rec.Code, rec.Body.String())
	}
	return rec
}

func (f *chanFixture) ownerID(t *testing.T, email string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := f.pool.QueryRow(context.Background(),
		`SELECT id FROM uptime.users WHERE email=$1`, email).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// verify performs the operator verification path — the same call the
// channel CLI wraps — straight against the repository.
var testKey = bytes.Repeat([]byte{9}, notification.KeyLen)

func (f *chanFixture) verify(ownerID uuid.UUID, channelID, chatID, receipt string) {
	f.t.Helper()
	ct, err := notification.EncryptDestination(testKey, []byte(chatID))
	if err != nil {
		f.t.Fatal(err)
	}
	cid, err := uuid.Parse(channelID)
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.crepo.VerifyChannel(context.Background(), ownerID, cid,
		ct, notification.MaskDestination(chatID),
		notification.KeyVersion1, receipt); err != nil {
		f.t.Fatalf("verify %s: %v", channelID, err)
	}
}

func TestOwnedChannels(t *testing.T) {
	f := newChanFixture(t, notification.Caps{
		PendingOwner: 3, PendingGlobal: 1000,
		RetainedOwner: 100, RetainedGlobal: 1000})
	defer f.cleanup()

	alice := f.newClient()
	aliceEmail := f.email("alice")
	alice.join(aliceEmail)
	aliceID := f.ownerID(t, aliceEmail)

	t.Run("create is pending metadata only", func(t *testing.T) {
		d := dataOf(t, alice.createChannel("telegram-main", http.StatusCreated))
		if d["status"] != "PENDING_VERIFICATION" || d["enabled"] != false {
			t.Fatalf("channel not pending: %v", d)
		}
		if d["destination_mask"] != nil {
			t.Fatalf("pending channel has mask: %v", d["destination_mask"])
		}
		for _, k := range []string{"destination", "chat_id", "ciphertext", "token", "receipt"} {
			if _, ok := d[k]; ok {
				t.Fatalf("response leaks field %q", k)
			}
		}
	})

	t.Run("browser cannot smuggle destination fields", func(t *testing.T) {
		for _, extra := range []string{"chat_id", "destination", "token", "destination_ciphertext"} {
			body := fmt.Sprintf(`{"label":"x","%s":"123"}`, extra)
			rec := alice.do(http.MethodPost, "/notification-channels", body, true)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s smuggle: %d %s", extra, rec.Code, rec.Body.String())
			}
		}
	})

	aChan := alice.channelID("alice-chan") // pending #2 for alice

	bob := f.newClient()
	bob.join(f.email("bob"))
	bChan := bob.channelID("bob-chan")

	t.Run("foreign channel indistinguishable from missing", func(t *testing.T) {
		rec := alice.do(http.MethodGet, "/notification-channels/"+bChan, "", false)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("foreign get: %d", rec.Code)
		}
		items := dataOf(t, alice.do(http.MethodGet, "/notification-channels", "", false))["items"].([]any)
		for _, it := range items {
			if it.(map[string]any)["id"] == bChan {
				t.Fatal("foreign channel in owner list")
			}
		}
	})

	t.Run("operator verify enables and masks only", func(t *testing.T) {
		f.verify(aliceID, aChan, "555123", "RECEIPT-1")
		d := dataOf(t, alice.do(http.MethodGet, "/notification-channels/"+aChan, "", false))
		if d["status"] != "VERIFIED" || d["enabled"] != true {
			t.Fatalf("not verified+enabled: %v", d)
		}
		if d["destination_mask"] != "•••5123" {
			t.Fatalf("mask: %v", d["destination_mask"])
		}
		if d["version"].(float64) != 2 {
			t.Fatalf("version: %v", d["version"])
		}
	})

	t.Run("pending cap counts tombstoned pending too", func(t *testing.T) {
		// alice: telegram-main (pending) + alice-chan (verified) →
		// pending counted = 1 of cap 3.
		p2 := alice.channelID("pending-2")
		p3 := alice.channelID("pending-3")
		if rec := alice.createChannel("pending-4", http.StatusConflict); errCode(t, rec) != "ALLOCATION_LIMIT_REACHED" {
			t.Fatalf("owner pending cap: %s", rec.Body.String())
		}
		// Tombstoned pending still counts: delete p2 → still at cap.
		alice.do(http.MethodDelete, "/notification-channels/"+p2,
			`{"expected_version":1}`, true)
		if rec := alice.createChannel("pending-4", http.StatusConflict); errCode(t, rec) != "ALLOCATION_LIMIT_REACHED" {
			t.Fatalf("tombstoned pending must still count: %s", rec.Body.String())
		}
		// Verifying p3 leaves the pending set → slot frees.
		f.verify(aliceID, p3, "777", "RECEIPT-2")
		alice.createChannel("pending-4", http.StatusCreated)
	})

	t.Run("disable preserves row, blocks eligibility", func(t *testing.T) {
		d := dataOf(t, alice.do(http.MethodPost,
			"/notification-channels/"+aChan+"/disable",
			`{"expected_version":2}`, true))
		if d["enabled"] != false || d["status"] != "DISABLED" {
			t.Fatalf("disable: %v", d)
		}
		mon := alice.createMonitor("m-dis")
		rec := alice.bind(mon["id"].(string), 1, []string{aChan}, http.StatusUnprocessableEntity)
		if errCode(t, rec) != "VALIDATION_ERROR" {
			t.Fatalf("disabled bind: %s", rec.Body.String())
		}
	})
}

func TestPendingChannelAllocationBudget(t *testing.T) {
	// Owner cap test: PendingOwner=2, generous global.
	f := newChanFixture(t, notification.Caps{
		PendingOwner: 2, PendingGlobal: 100000,
		RetainedOwner: 1000, RetainedGlobal: 100000})
	defer f.cleanup()
	c := f.newClient()
	c.join(f.email("pending-cap"))
	c.channelID("p1")
	c.channelID("p2")
	if rec := c.createChannel("p3", http.StatusConflict); errCode(t, rec) != "ALLOCATION_LIMIT_REACHED" {
		t.Fatalf("owner pending cap: %s", rec.Body.String())
	}

	// Global cap test: separate fixture whose global cap is
	// current-pending + 2 — the owner's cap is unreachable first.
	g := newChanFixture(t, notification.Caps{
		PendingOwner:  1000,
		PendingGlobal: pendingCount(t, f.pool) + 2,
		RetainedOwner: 1000, RetainedGlobal: 100000})
	defer g.cleanup()
	gc := g.newClient()
	gc.join(g.email("global-cap"))
	gc.channelID("g1")
	gc.channelID("g2")
	if rec := gc.createChannel("g3", http.StatusConflict); errCode(t, rec) != "ALLOCATION_LIMIT_REACHED" {
		t.Fatalf("global pending cap: %s", rec.Body.String())
	}
}

func TestAtomicChannelBinding(t *testing.T) {
	f := newChanFixture(t, notification.Caps{
		PendingOwner: 10, PendingGlobal: 1000,
		RetainedOwner: 1000, RetainedGlobal: 10000})
	defer f.cleanup()

	owner := f.newClient()
	ownerEmail := f.email("bind")
	owner.join(ownerEmail)
	ownerID := f.ownerID(t, ownerEmail)
	foreign := f.newClient()
	foreignEmail := f.email("bind-f")
	foreign.join(foreignEmail)
	foreignID := f.ownerID(t, foreignEmail)

	mon := owner.createMonitor("m1")
	monID := mon["id"].(string)
	putPath := "/monitors/" + monID + "/notification-channels"

	v1 := owner.channelID("v1")
	f.verify(ownerID, v1, "111111", "R1")
	v2 := owner.channelID("v2")
	f.verify(ownerID, v2, "222222", "R2")
	pend := owner.channelID("pend")
	fChan := foreign.channelID("foreign")
	f.verify(foreignID, fChan, "999999", "R3")

	t.Run("eligible set binds once, generation++", func(t *testing.T) {
		d := dataOf(t, owner.bind(monID, 1, []string{v1, v2}, http.StatusOK))
		if d["generation"].(float64) != 2 || d["monitor_id"] != monID {
			t.Fatalf("bind output: %v", d)
		}
		if len(d["channel_ids"].([]any)) != 2 {
			t.Fatalf("channel_ids: %v", d)
		}
	})

	t.Run("pending, foreign, missing all reject without partial update", func(t *testing.T) {
		for _, ids := range [][]string{{pend}, {fChan}, {uuid.NewString()}, {v1, pend}} {
			rec := owner.bind(monID, 2, ids, http.StatusUnprocessableEntity)
			if errCode(t, rec) != "VALIDATION_ERROR" {
				t.Fatalf("bind %v: %s", ids, rec.Body.String())
			}
		}
		// Rejected binds must not move generation or bindings.
		d := dataOf(t, owner.bind(monID, 2, []string{}, http.StatusOK))
		if d["generation"].(float64) != 3 {
			t.Fatalf("gen drifted on rejects: %v", d)
		}
		if len(d["channel_ids"].([]any)) != 0 {
			t.Fatalf("empty unbind: %v", d)
		}
	})

	t.Run("stale generation conflicts and health is preserved", func(t *testing.T) {
		owner.bind(monID, 3, []string{v1}, http.StatusOK) // gen 4
		rec := owner.bind(monID, 3, []string{v2}, http.StatusConflict)
		if errCode(t, rec) != "CONFLICT" {
			t.Fatalf("stale gen: %s", rec.Body.String())
		}
		d := dataOf(t, owner.do(http.MethodGet, "/monitors/"+monID, "", false))
		if d["health"] != "UNKNOWN" || d["generation"].(float64) != 4 {
			t.Fatalf("bind drifted health/gen: %v", d)
		}
	})

	t.Run("same-generation writers — exactly one wins", func(t *testing.T) {
		var wg sync.WaitGroup
		won := atomic.Int32{}
		for i, ids := range [][]string{{v1}, {v2}, {v1, v2}} {
			wg.Add(1)
			go func(i int, ids []string) {
				defer wg.Done()
				body, _ := json.Marshal(map[string]any{
					"expected_generation": 4, "channel_ids": ids})
				req, _ := http.NewRequest(http.MethodPut,
					owner.srv.URL+putPath, bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Origin", owner.origin)
				if owner.csrfCk != nil {
					req.AddCookie(owner.csrfCk)
				}
				req.Header.Set("X-CSRF-Token", owner.csrfTok)
				if owner.sessCk != nil {
					req.AddCookie(owner.sessCk)
				}
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					return
				}
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					won.Add(1)
				}
			}(i, ids)
		}
		wg.Wait()
		if won.Load() != 1 {
			t.Fatalf("concurrent binds: %d winners", won.Load())
		}
	})
}

func TestAtomicChannelBindingGeneration(t *testing.T) {
	f := newChanFixture(t, notification.Caps{
		PendingOwner: 10, PendingGlobal: 1000,
		RetainedOwner: 1000, RetainedGlobal: 10000})
	defer f.cleanup()
	c := f.newClient()
	cEmail := f.email("genrace")
	c.join(cEmail)
	cID := f.ownerID(t, cEmail)

	// Drive the monitor to generation 7 via three pause/resume cycles.
	mon := c.createMonitor("gr")
	monID := mon["id"].(string)
	for i := int64(1); i <= 5; i += 2 {
		body := fmt.Sprintf(`{"expected_generation":%d}`, i)
		if rec := c.do(http.MethodPost, "/monitors/"+monID+"/pause", body, true); rec.Code != http.StatusOK {
			t.Fatalf("pause gen%d: %s", i, rec.Body.String())
		}
		body = fmt.Sprintf(`{"expected_generation":%d}`, i+1)
		if rec := c.do(http.MethodPost, "/monitors/"+monID+"/resume", body, true); rec.Code != http.StatusOK {
			t.Fatalf("resume gen%d: %s", i+1, rec.Body.String())
		}
	}
	d := dataOf(t, c.do(http.MethodGet, "/monitors/"+monID, "", false))
	if d["generation"].(float64) != 7 {
		t.Fatalf("setup generation: %v", d)
	}

	v := c.channelID("gv")
	f.verify(cID, v, "42", "RX")

	// Three generation-7 writers — PUT bind, PUT unbind, PATCH rename.
	type req struct{ method, path, body string }
	writers := []req{
		{"PUT", "/monitors/" + monID + "/notification-channels",
			fmt.Sprintf(`{"expected_generation":7,"channel_ids":[%q]}`, v)},
		{"PUT", "/monitors/" + monID + "/notification-channels",
			`{"expected_generation":7,"channel_ids":[]}`},
		{"PATCH", "/monitors/" + monID,
			`{"expected_generation":7,"name":"gr-renamed"}`},
	}
	var wg sync.WaitGroup
	won := atomic.Int32{}
	for _, w := range writers {
		wg.Add(1)
		go func(w req) {
			defer wg.Done()
			r, _ := http.NewRequest(w.method, c.srv.URL+w.path,
				strings.NewReader(w.body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", c.origin)
			if c.csrfCk != nil {
				r.AddCookie(c.csrfCk)
			}
			r.Header.Set("X-CSRF-Token", c.csrfTok)
			if c.sessCk != nil {
				r.AddCookie(c.sessCk)
			}
			resp, err := http.DefaultClient.Do(r)
			if err != nil {
				return
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				won.Add(1)
			}
		}(w)
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Fatalf("gen-7 race: %d winners", won.Load())
	}
	if d := dataOf(t, c.do(http.MethodGet, "/monitors/"+monID, "", false)); d["generation"].(float64) != 8 {
		t.Fatalf("final generation: %v", d)
	}
}
