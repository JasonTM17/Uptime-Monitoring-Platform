//go:build integration

package admin_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/admin"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/auth"
)

// Positive-path HTTP coverage over the real DB: the query surface
// had service-level integration coverage but no transport evidence —
// these subtests drive the mounted mux end to end, so permission
// wiring, envelopes, and 404/403 mapping are all real.

func adminMuxFor(t *testing.T, conn *pgx.Conn, actor admin.ActorRef) *httptest.Server {
	t.Helper()
	gate := fakeGate{principal: auth.Principal{
		User: auth.User{ID: actor.UserID},
		Session: auth.Session{ID: actor.SessionID,
			SecurityVersion: actor.SecurityVersion},
	}}
	h := admin.NewRolesHandler(conn, gate, nil, 1<<20,
		admin.QuotaCeilings{}, nil)
	return httptest.NewServer(h.Mux())
}

func adminGet(t *testing.T, srv *httptest.Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.Config.Handler.ServeHTTP(rec,
		httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestAdminQueryTransport(t *testing.T) {
	conn := connect(t)
	sec, cleanup := actorWithRole(t, conn, "qt-sec", secAdminPreset)
	defer cleanup()
	viewer, vcleanup := actorWithRole(t, conn, "qt-view", viewerPreset)
	defer vcleanup()

	srv := adminMuxFor(t, conn, sec)
	defer srv.Close()

	t.Run("overview serves the platform projection", func(t *testing.T) {
		rec := adminGet(t, srv, "/admin/overview")
		if rec.Code != http.StatusOK {
			t.Fatalf("overview: %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("roles catalog lists the presets", func(t *testing.T) {
		rec := adminGet(t, srv, "/admin/roles")
		if rec.Code != http.StatusOK {
			t.Fatalf("roles: %d %s", rec.Code, rec.Body.String())
		}
		var env struct {
			Data struct {
				Roles []struct {
					Code string `json:"code"`
				} `json:"roles"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(env.Data.Roles) < 5 {
			t.Fatalf("catalog: %+v", env.Data)
		}
	})

	t.Run("users list + single-get + missing subject", func(t *testing.T) {
		rec := adminGet(t, srv, "/admin/users")
		if rec.Code != http.StatusOK {
			t.Fatalf("users: %d %s", rec.Code, rec.Body.String())
		}
		var env struct {
			Data struct {
				Users []struct {
					ID string `json:"id"`
				} `json:"users"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(env.Data.Users) == 0 {
			t.Fatal("users list empty — fixture users exist")
		}

		rec = adminGet(t, srv, "/admin/users/"+viewer.UserID.String())
		if rec.Code != http.StatusOK {
			t.Fatalf("getUser: %d %s", rec.Code, rec.Body.String())
		}
		rec = adminGet(t, srv, "/admin/users/"+uuid.NewString())
		if rec.Code != http.StatusNotFound {
			t.Fatalf("missing user: %d", rec.Code)
		}
	})

	t.Run("audit list + detail + missing id", func(t *testing.T) {
		rec := adminGet(t, srv, "/admin/audit-events")
		if rec.Code != http.StatusOK {
			t.Fatalf("audit list: %d %s", rec.Code, rec.Body.String())
		}
		rec = adminGet(t, srv, "/admin/audit-events/"+uuid.NewString())
		if rec.Code != http.StatusNotFound {
			t.Fatalf("missing event: %d", rec.Code)
		}
	})

	t.Run("monitors + operations lists serve envelopes", func(t *testing.T) {
		for _, path := range []string{"/admin/monitors", "/admin/operations"} {
			rec := adminGet(t, srv, path)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
			}
		}
	})

	t.Run("outbox needs deliveries:read — operator, not secadmin", func(t *testing.T) {
		// SEC_ADMIN lacks deliveries:read by design; the deny is the
		// contract, then the OPERATOR read proves the positive path.
		rec := adminGet(t, srv, "/admin/outbox")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("secadmin outbox must be denied: %d", rec.Code)
		}
		op, ocleanup := actorWithRole(t, conn, "qt-op", operatorPreset)
		defer ocleanup()
		osrv := adminMuxFor(t, conn, op)
		defer osrv.Close()
		rec = adminGet(t, osrv, "/admin/outbox")
		if rec.Code != http.StatusOK {
			t.Fatalf("operator outbox: %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("viewer is denied the users surface", func(t *testing.T) {
		vsrv := adminMuxFor(t, conn, viewer)
		defer vsrv.Close()
		rec := adminGet(t, vsrv, "/admin/users")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("viewer users: %d %s", rec.Code, rec.Body.String())
		}
		// platform:read is allowed — the boundary is real.
		rec = adminGet(t, vsrv, "/admin/overview")
		if rec.Code != http.StatusOK {
			t.Fatalf("viewer overview: %d %s", rec.Code, rec.Body.String())
		}
	})
}

// Write-route transport coverage. Domain-level tests exercise the
// privileged functions directly, which cannot see the two pieces that
// only exist at the HTTP boundary: the CSRF guard wrapping mutations
// and the Idempotency-Key header reaching the ledger. A regression in
// either would ship silently under the existing suite.

func TestAdminWriteTransport(t *testing.T) {
	conn := connect(t)
	// The last-superadmin invariant is a post-mutation aggregate
	// check, not a subject check: a suspend fails platform-wide when
	// no ACTIVE superadmin remains. A superadmin actor satisfies it.
	sec, cleanup := superActor(t, conn, "wt-sec")
	defer cleanup()
	victim, vcleanup := authFixture(t, conn, "wt-target")
	defer vcleanup()

	csrf := auth.NewCSRFManager(
		[]byte("0123456789abcdef0123456789abcdef"),
		time.Hour, false, []string{"https://app.test"})
	gate := fakeGate{principal: auth.Principal{
		User: auth.User{ID: sec.UserID},
		Session: auth.Session{ID: sec.SessionID,
			SecurityVersion: sec.SecurityVersion},
	}}
	mux := admin.NewRolesHandler(conn, gate, csrf, 1<<20,
		admin.QuotaCeilings{}, nil).Mux()

	ctx := context.Background()
	var version int64
	if err := conn.QueryRow(ctx,
		`SELECT version FROM uptime.users WHERE id=$1`,
		victim.UserID).Scan(&version); err != nil {
		t.Fatal(err)
	}
	path := "/admin/users/" + victim.UserID.String() + "/suspend"
	body := func(reason string) string {
		return `{"expected_version":` + itoa64(version) +
			`,"reason":"` + reason + `"}`
	}

	issue := func() (cookie, token string) {
		t.Helper()
		rec := httptest.NewRecorder()
		tok, err := csrf.Issue(rec)
		if err != nil {
			t.Fatal(err)
		}
		var ck string
		for _, c := range rec.Result().Cookies() {
			if strings.HasPrefix(c.Name, "uptime_csrf") {
				ck = c.Name + "=" + c.Value
			}
		}
		if ck == "" {
			t.Fatal("csrf issue set no cookie")
		}
		return ck, tok
	}
	post := func(idemKey, payload string, withCSRF bool) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path,
			strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		if idemKey != "" {
			req.Header.Set("Idempotency-Key", idemKey)
		}
		if withCSRF {
			ck, tok := issue()
			req.Header.Set("Cookie", ck)
			req.Header.Set("X-CSRF-Token", tok)
			req.Header.Set("Origin", "https://app.test")
		}
		mux.ServeHTTP(rec, req)
		return rec
	}

	t.Run("mutation without csrf is 403 before session", func(t *testing.T) {
		rec := post("", body("no csrf"), false)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("no csrf: %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("suspend commits and replays under one key", func(t *testing.T) {
		key := "wt-" + uuid.NewString()
		first := post(key, body("first"), true)
		if first.Code != http.StatusOK {
			t.Fatalf("suspend: %d %s", first.Code, first.Body.String())
		}
		// Same key + same body replays the recorded response — no
		// second mutation, no second audit row.
		replay := post(key, body("first"), true)
		if replay.Code != http.StatusOK ||
			replay.Body.String() != first.Body.String() {
			t.Fatalf("replay diverged: %d %s vs %d %s",
				replay.Code, replay.Body.String(),
				first.Code, first.Body.String())
		}
		var audits int
		if err := conn.QueryRow(ctx, `
			SELECT count(*) FROM uptime.audit_events
			WHERE action='account.suspend' AND subject_id=$1`,
			victim.UserID.String()).Scan(&audits); err != nil {
			t.Fatal(err)
		}
		if audits != 1 {
			t.Fatalf("audit rows = %d, want exactly 1 after replay", audits)
		}
		// Same key + different body is an idempotency conflict.
		conflict := post(key, body("tampered"), true)
		if conflict.Code != http.StatusConflict {
			t.Fatalf("key reuse with new body: %d %s",
				conflict.Code, conflict.Body.String())
		}
	})

	t.Run("missing idempotency key is 422 not silent", func(t *testing.T) {
		v2, vc := authFixture(t, conn, "wt-nokey")
		defer vc()
		var v2ver int64
		if err := conn.QueryRow(ctx,
			`SELECT version FROM uptime.users WHERE id=$1`,
			v2.UserID).Scan(&v2ver); err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost,
			"/admin/users/"+v2.UserID.String()+"/suspend",
			strings.NewReader(`{"expected_version":`+itoa64(v2ver)+
				`,"reason":"no key"}`))
		req.Header.Set("Content-Type", "application/json")
		ck, tok := issue()
		req.Header.Set("Cookie", ck)
		req.Header.Set("X-CSRF-Token", tok)
		req.Header.Set("Origin", "https://app.test")
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("no idempotency key: %d %s",
				rec.Code, rec.Body.String())
		}
	})
}

func itoa64(v int64) string { return strconv.FormatInt(v, 10) }
