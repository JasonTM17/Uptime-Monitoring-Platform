//go:build integration

package notification

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/auth"
	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/config"
)

// gateFor returns a RequireSession stub injecting the real-session
// principal — authentication itself is not under test here.
type gateFor struct{ p auth.Principal }

func (g gateFor) RequireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if _, ok := auth.PrincipalFromContext(ctx); !ok {
			ctx = auth.ContextWithPrincipal(ctx, g.p)
		}
		next(w, r.WithContext(ctx))
	}
}

func (g gateFor) WithActorLock(_ context.Context, _ auth.Principal,
	_ func(tx pgx.Tx, u auth.User) error) error {
	return errors.New("WithActorLock not implemented in test gate")
}

// lockedGate keeps authentication as a captured middleware snapshot while
// exercising the real database-backed mutation fence.
type lockedGate struct {
	gateFor
	svc *auth.Service
}

func (g lockedGate) WithActorLock(ctx context.Context, p auth.Principal,
	fn func(pgx.Tx, auth.User) error) error {
	return g.svc.WithActorLock(ctx, p, fn)
}

func testActorGate(pool *pgxpool.Pool, p auth.Principal) lockedGate {
	svc := auth.NewService(auth.NewRepository(pool, 3*time.Second), nil,
		config.AuthConfig{}, 10)
	return lockedGate{gateFor: gateFor{p}, svc: svc}
}

// rollbackGate aborts after the intent callback to prove the HTTP write
// belongs to the authorization transaction rather than a separate commit.
type rollbackGate struct{ lockedGate }

func (g rollbackGate) WithActorLock(ctx context.Context, p auth.Principal,
	fn func(pgx.Tx, auth.User) error) error {
	return g.svc.WithActorLock(ctx, p, func(tx pgx.Tx, u auth.User) error {
		if err := fn(tx, u); err != nil {
			return err
		}
		return auth.ErrInvalidSession
	})
}

func TestOwnNotificationTestIntentRollsBackWithActorTransaction(t *testing.T) {
	ops, pool := opsFor(t)
	c := conn(t)
	f := seedBase(t, c)
	ch := mkChannel(t, c, f, "VERIFIED", true, true)
	fresh := time.Minute
	p := testSession(t, pool, f.userID, &fresh)
	h := NewTestHandler(ops, rollbackGate{testActorGate(pool, p)}, nil,
		DefaultTestRate, 1<<16, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/notification-channels/"+ch.String()+"/test",
		strings.NewReader(`{"monitor_id":"`+f.monID.String()+`"}`))
	req.Header.Set("Content-Type", "application/json")
	h.Mux().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("aborted actor transaction got %d, want 401", rec.Code)
	}
	var count int
	if err := c.QueryRow(context.Background(), `SELECT count(*)
		FROM uptime.notification_outbox WHERE channel_id=$1`, ch).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("actor rollback left %d persisted intents", count)
	}
}

func TestOwnNotificationTestRejectsStaleActor(t *testing.T) {
	for _, tc := range []struct {
		name string
		sql  string
	}{
		{"revoked session", `UPDATE uptime.sessions SET revoked_at=clock_timestamp() WHERE id=$1`},
		{"changed security epoch", `UPDATE uptime.users SET security_version=security_version+1 WHERE id=$1`},
		{"suspended account", `UPDATE uptime.users SET status='DISABLED',disabled_at=clock_timestamp() WHERE id=$1`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ops, pool := opsFor(t)
			c := conn(t)
			f := seedBase(t, c)
			ch := mkChannel(t, c, f, "VERIFIED", true, true)
			fresh := time.Minute
			p := testSession(t, pool, f.userID, &fresh)
			// Authentication happened before this committed revocation. The
			// handler must distrust that snapshot before persisting an intent.
			id := f.userID
			if tc.name == "revoked session" {
				id = p.Session.ID
			}
			if _, err := c.Exec(context.Background(), tc.sql, id); err != nil {
				t.Fatal(err)
			}
			h := NewTestHandler(ops, testActorGate(pool, p), nil,
				DefaultTestRate, 1<<16, nil)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("POST",
				"/notification-channels/"+ch.String()+"/test",
				strings.NewReader(`{"monitor_id":"`+f.monID.String()+`"}`))
			req.Header.Set("Content-Type", "application/json")
			h.Mux().ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("stale actor got %d, want 401: %s", rec.Code, rec.Body.String())
			}
			var count int
			if err := c.QueryRow(context.Background(), `
				SELECT count(*) FROM uptime.notification_outbox
				WHERE channel_id=$1 AND event_kind='TEST'`, ch).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Errorf("stale actor persisted %d TEST intents, want zero", count)
			}
		})
	}
}

// testSession seeds a sessions row for the user, optionally with a
// fresh recent_auth_at, and returns the principal.
func testSession(t *testing.T, pool *pgxpool.Pool,
	owner uuid.UUID, recentAgo *time.Duration) auth.Principal {
	t.Helper()
	sid := uuid.New()
	tok := sha256.Sum256([]byte(uuid.NewString()))
	var recent interface{}
	if recentAgo != nil {
		recent = time.Now().Add(-*recentAgo)
	}
	var sec int64
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO uptime.sessions
		  (id,user_id,token_hash,security_version,recent_auth_at,
		   expires_at,idle_expires_at)
		VALUES ($1,$2,$3,1,$4,now()+interval '1 hour',
		  now()+interval '1 hour')
		RETURNING security_version`,
		sid, owner, tok[:], recent).Scan(&sec); err != nil {
		t.Fatal(err)
	}
	return auth.Principal{
		User:    auth.User{ID: owner},
		Session: auth.Session{ID: sid, SecurityVersion: sec},
	}
}

func TestOwnNotificationTestRoute(t *testing.T) {
	ops, pool := opsFor(t)
	c := conn(t)
	f := seedBase(t, c)
	ch := mkChannel(t, c, f, "VERIFIED", true, true)
	fresh := time.Minute
	p := testSession(t, pool, f.userID, &fresh)

	h := NewTestHandler(ops, testActorGate(pool, p), nil,
		TestRate{PerChannelCooldown: time.Minute, GlobalOutstanding: 50},
		1<<16, nil)
	mux := h.Mux()

	call := func(principal auth.Principal, monitorID string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		b := strings.NewReader(`{"monitor_id":"` + monitorID + `"}`)
		req := httptest.NewRequest("POST",
			"/notification-channels/"+ch.String()+"/test", b)
		req.Header.Set("Content-Type", "application/json")
		mux.ServeHTTP(rec, req.WithContext(
			auth.ContextWithPrincipal(req.Context(), principal)))
		return rec
	}

	t.Run("owned bound verified recent-auth queues intent", func(t *testing.T) {
		rec := call(p, f.monID.String())
		if rec.Code != http.StatusAccepted {
			t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Data struct {
				IntentID string `json:"intent_id"`
				State    string `json:"state"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.Data.IntentID == "" || resp.Data.State != "PENDING" {
			t.Fatalf("unexpected response: %s", rec.Body.String())
		}
		// The intent is persisted, not sent.
		var state string
		if err := c.QueryRow(context.Background(), `
			SELECT state FROM uptime.notification_outbox WHERE id=$1`,
			resp.Data.IntentID).Scan(&state); err != nil || state != "PENDING" {
			t.Fatalf("intent state=%q err=%v", state, err)
		}
		// Response carries no raw destination.
		if strings.Contains(rec.Body.String(), "destination") ||
			strings.Contains(rec.Body.String(), "ciphertext") {
			t.Fatal("response leaked recipient data")
		}
	})

	t.Run("same window is rate limited", func(t *testing.T) {
		// The per-channel cooldown (1/min) fires before the dedup
		// window — a repeat in the same window is honestly 429.
		rec := call(p, f.monID.String())
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("missing recent-auth is 403", func(t *testing.T) {
		stale := 10 * time.Minute
		p2 := testSession(t, pool, f.userID, &stale)
		rec := call(p2, f.monID.String())
		if rec.Code != http.StatusForbidden {
			t.Fatalf("got %d, want 403 REAUTH_REQUIRED", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "REAUTH_REQUIRED") {
			t.Fatalf("envelope: %s", rec.Body.String())
		}
	})

	t.Run("foreign monitor is 404", func(t *testing.T) {
		rec := call(p, uuid.NewString())
		if rec.Code != http.StatusNotFound {
			t.Fatalf("got %d, want 404", rec.Code)
		}
	})

	t.Run("unbound channel is 409", func(t *testing.T) {
		unbound := mkChannel(t, c, f, "VERIFIED", true, false)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST",
			"/notification-channels/"+unbound.String()+"/test",
			strings.NewReader(`{"monitor_id":"`+f.monID.String()+`"}`))
		req.Header.Set("Content-Type", "application/json")
		mux.ServeHTTP(rec, req.WithContext(
			auth.ContextWithPrincipal(req.Context(), p)))
		if rec.Code != http.StatusConflict {
			t.Fatalf("got %d, want 409", rec.Code)
		}
	})

	t.Run("unverified channel is 409", func(t *testing.T) {
		pend := mkChannel(t, c, f, "PENDING_VERIFICATION", false, true)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST",
			"/notification-channels/"+pend.String()+"/test",
			strings.NewReader(`{"monitor_id":"`+f.monID.String()+`"}`))
		req.Header.Set("Content-Type", "application/json")
		mux.ServeHTTP(rec, req.WithContext(
			auth.ContextWithPrincipal(req.Context(), p)))
		if rec.Code != http.StatusConflict {
			t.Fatalf("got %d, want 409", rec.Code)
		}
	})

	t.Run("no raw recipient in any response", func(t *testing.T) {
		rec := call(p, f.monID.String())
		body := rec.Body.String()
		if strings.Contains(body, "chat") || strings.Contains(body, "destination") ||
			strings.Contains(body, "+84") {
			t.Fatalf("recipient data leaked: %s", body)
		}
	})
}
