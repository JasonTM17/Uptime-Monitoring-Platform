//go:build integration

package admin_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/admin"
	"github.com/google/uuid"
)

func TestAdminQueryPermissions(t *testing.T) {
	conn := connect(t)
	ctx := context.Background()
	now := time.Now()

	// Every preset role maps to exactly its matrix allow/deny set.
	cases := []struct {
		roleID string
		name   string
		perm   string // probed capability
		allow  bool
	}{
		{viewerPreset, "viewer overview", "platform:read", true},
		{viewerPreset, "viewer users denied", "users:read", false},
		{viewerPreset, "viewer audit denied", "audit:read", false},
		{operatorPreset, "operator deliveries", "deliveries:read", true},
		{operatorPreset, "operator users denied", "users:read", false},
		{secAdminPreset, "secadmin users", "users:read", true},
		{secAdminPreset, "secadmin audit", "audit:read", true},
	}
	for _, c := range cases {
		actor, cleanup := actorWithRole(t, conn, "c63-"+c.name[:4], c.roleID)
		var err error
		switch c.perm {
		case "platform:read":
			_, err = admin.Overview(ctx, conn, actor, now)
		case "users:read":
			_, _, err = admin.ListUsers(ctx, conn, actor,
				admin.UsersFilter{Limit: 1}, now)
		case "deliveries:read":
			_, _, err = admin.ListOutbox(ctx, conn, actor,
				admin.OutboxFilter{Limit: 1}, now)
		case "audit:read":
			_, _, err = admin.ListAuditEvents(ctx, conn, actor,
				admin.AuditFilter{Limit: 1}, now)
		}
		if c.allow && err != nil {
			t.Fatalf("%s: allowed but got %v", c.name, err)
		}
		if !c.allow && !errors.Is(err, admin.ErrForbidden) {
			t.Fatalf("%s: want ErrForbidden, got %v", c.name, err)
		}
		cleanup()
	}
}

func TestAdminQueryPagination(t *testing.T) {
	conn := connect(t)
	actor, cleanup := superActor(t, conn, "c63-page")
	defer cleanup()
	ctx := context.Background()
	now := time.Now()

	// Seed several users in one second (equal timestamps stress the
	// id tiebreak — keyset (created_at,id) must not dup or skip).
	var ids []uuid.UUID
	var cleanups []func()
	for i := 0; i < 5; i++ {
		u, c := plainUser(t, conn, "c63-pg")
		ids = append(ids, u.UserID)
		cleanups = append(cleanups, c)
	}
	defer func() {
		for _, c := range cleanups {
			c()
		}
	}()
	// Force equal created_at across the batch.
	if _, err := conn.Exec(ctx, `
		UPDATE uptime.users SET created_at=$1 WHERE id=ANY($2)`,
		now.Add(-time.Hour).UTC(), ids); err != nil {
		t.Fatal(err)
	}

	seen := map[uuid.UUID]bool{}
	cursor := ""
	pages := 0
	for {
		rows, next, err := admin.ListUsers(ctx, conn, actor,
			admin.UsersFilter{Q: "c63-pg", Limit: 2, Cursor: cursor}, now)
		if err != nil {
			t.Fatalf("page %d: %v", pages, err)
		}
		for _, r := range rows {
			if seen[r.ID] {
				t.Fatalf("duplicate row across pages: %s", r.ID)
			}
			seen[r.ID] = true
		}
		pages++
		if next == "" || pages > 10 {
			cursor = next
			break
		}
		cursor = next
	}
	if len(seen) != 5 {
		t.Fatalf("saw %d rows, want 5 (equal-timestamp tiebreak)", len(seen))
	}

	// Cursor bound to a different filter set must be rejected, not
	// silently applied.
	_, next, err := admin.ListUsers(ctx, conn, actor,
		admin.UsersFilter{Q: "c63-pg", Limit: 2}, now)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = admin.ListUsers(ctx, conn, actor,
		admin.UsersFilter{Q: "other", Limit: 2, Cursor: next}, now)
	if !errors.Is(err, admin.ErrCursor) {
		t.Fatalf("filter-mismatched cursor: want ErrCursor, got %v", err)
	}
	// Malformed cursor → 400-class.
	_, _, err = admin.ListUsers(ctx, conn, actor,
		admin.UsersFilter{Cursor: "!!!not-a-cursor"}, now)
	if !errors.Is(err, admin.ErrCursor) {
		t.Fatalf("malformed cursor: want ErrCursor, got %v", err)
	}
	// Unknown filter values → 400/422, not silent.
	_, _, err = admin.ListUsers(ctx, conn, actor,
		admin.UsersFilter{Status: "SUSPENDED"}, now)
	if !errors.Is(err, admin.ErrValidation) {
		t.Fatalf("bad status: want ErrValidation, got %v", err)
	}
	// Audit window bound.
	_, _, err = admin.ListAuditEvents(ctx, conn, actor,
		admin.AuditFilter{From: "2020-01-01T00:00:00Z",
			To: "2026-01-01T00:00:00Z"}, now)
	if !errors.Is(err, admin.ErrValidation) {
		t.Fatalf("unbounded window: want ErrValidation, got %v", err)
	}

	// Audit keyset across pages: no duplicates, strictly descending —
	// the equal-timestamp tiebreak must never skip a row either.
	seenA := map[uuid.UUID]bool{}
	cursor = ""
	var prevKey time.Time
	for pages := 0; pages < 20; pages++ {
		rows, next, err := admin.ListAuditEvents(ctx, conn, actor,
			admin.AuditFilter{Limit: 2, Cursor: cursor}, now)
		if err != nil {
			t.Fatalf("audit page %d: %v", pages, err)
		}
		for _, a := range rows {
			if seenA[a.ID] {
				t.Fatalf("audit dup across pages: %s", a.ID)
			}
			seenA[a.ID] = true
			if !prevKey.IsZero() && a.CreatedAt.After(prevKey) {
				t.Fatal("audit rows not descending")
			}
			prevKey = a.CreatedAt
		}
		if next == "" {
			break
		}
		cursor = next
	}
}

func TestAdminRedaction(t *testing.T) {
	conn := connect(t)
	actor, cleanup := superActor(t, conn, "c63-red")
	defer cleanup()
	owner, oc := plainUser(t, conn, "c63-rd")
	defer oc()
	ctx := context.Background()
	now := time.Now()

	// A monitor whose URL carries a query secret — the projection
	// must reduce it to scheme+host.
	var monID uuid.UUID
	if err := conn.QueryRow(ctx, `
		INSERT INTO uptime.monitors(id,user_id,name,target_url,method,
		  interval_seconds,timeout_seconds,next_check_at)
		VALUES (gen_random_uuid(),$1,'m',
		  'https://api.example.test/check?sig=zzz-canary-value','GET',60,5,now())
		RETURNING id`, owner.UserID).Scan(&monID); err != nil {
		t.Fatal(err)
	}
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.Exec(c, `DELETE FROM uptime.schedule_segments WHERE monitor_id=$1`, monID)
		_, _ = conn.Exec(c, `DELETE FROM uptime.check_runs WHERE monitor_id=$1`, monID)
		_, _ = conn.Exec(c, `DELETE FROM uptime.monitors WHERE id=$1`, monID)
	}()

	rows, _, err := admin.ListGlobalMonitors(ctx, conn, actor,
		admin.MonitorsFilter{Limit: 100}, now)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, m := range rows {
		if m.ID == monID {
			found = true
			if m.Target != "https://api.example.test" {
				t.Fatalf("target not redacted: %q", m.Target)
			}
		}
	}
	if !found {
		t.Fatal("seeded monitor missing from global list")
	}
}

func TestAdminFreshness(t *testing.T) {
	conn := connect(t)
	actor, cleanup := superActor(t, conn, "c63-fresh")
	defer cleanup()
	ctx := context.Background()
	now := time.Now()

	// Seed engine_control with an old heartbeat — freshness must read
	// "stale", never false-green.
	if _, err := conn.Exec(ctx, `
		INSERT INTO uptime.engine_control(id,epoch,heartbeat_at)
		VALUES (1,1,now()-interval '10 minutes')
		ON CONFLICT (id) DO UPDATE SET heartbeat_at=now()-interval '10 minutes'`); err != nil {
		t.Fatal(err)
	}
	ov, err := admin.Overview(ctx, conn, actor, now)
	if err != nil {
		t.Fatal(err)
	}
	if ov.Engine.Freshness != "stale" {
		t.Fatalf("stale heartbeat reported %q", ov.Engine.Freshness)
	}
	if !ov.Database.Reachable {
		t.Fatal("reachable DB reported unreachable")
	}

	// Snapshot surfaces the same honest freshness.
	snap, err := admin.OperationsSnapshot(ctx, conn, actor, now)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Engine.Freshness != "stale" {
		t.Fatalf("snapshot freshness=%q", snap.Engine.Freshness)
	}
	if snap.Rollup.Freshness == "" {
		t.Fatal("rollup freshness missing")
	}

	// A fresh heartbeat flips to "fresh".
	if _, err := conn.Exec(ctx, `
		UPDATE uptime.engine_control SET heartbeat_at=clock_timestamp()
		WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	ov, _ = admin.Overview(ctx, conn, actor, now)
	if ov.Engine.Freshness != "fresh" {
		t.Fatalf("live heartbeat reported %q", ov.Engine.Freshness)
	}

	// No engine_control row at all → "absent", not "healthy".
	if _, err := conn.Exec(ctx, `DELETE FROM uptime.engine_control WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.Exec(c, `
			INSERT INTO uptime.engine_control(id,epoch) VALUES (1,1)
			ON CONFLICT (id) DO NOTHING`)
	}()
	ov, _ = admin.Overview(ctx, conn, actor, now)
	if ov.Engine.Freshness != "absent" {
		t.Fatalf("missing engine_control reported %q", ov.Engine.Freshness)
	}
}

// TestAdminDetailQueries covers the single-subject admin GETs that
// previously had no coverage at any level: GetUser, GetAuditEvent,
// ListRoleCatalog — allowed actor, denied actor, and missing subject.
func TestAdminDetailQueries(t *testing.T) {
	conn := connect(t)
	ctx := context.Background()
	now := time.Now()

	sec, cleanup := actorWithRole(t, conn, "dq-sec", secAdminPreset)
	defer cleanup()
	viewer, vcleanup := authFixture(t, conn, "dq-view")
	defer vcleanup()

	t.Run("GetUser returns subject detail under users:read", func(t *testing.T) {
		d, err := admin.GetUser(ctx, conn, sec, viewer.UserID, now)
		if err != nil {
			t.Fatalf("secadmin GetUser: %v", err)
		}
		if d.ID != viewer.UserID || d.Email == "" {
			t.Fatalf("wrong subject %+v", d)
		}
		if len(d.Roles) == 0 || d.Roles[0] != "VIEWER" {
			t.Fatalf("roles projection %+v", d.Roles)
		}
		if _, err := admin.GetUser(ctx, conn, viewer, sec.UserID, now); !errors.Is(err, admin.ErrForbidden) {
			t.Fatalf("viewer must be denied, got %v", err)
		}
		if _, err := admin.GetUser(ctx, conn, sec, uuid.New(), now); !errors.Is(err, admin.ErrSubjectRevoked) {
			t.Fatalf("missing subject must be 404-ish, got %v", err)
		}
	})

	t.Run("GetAuditEvent returns one row under audit:read", func(t *testing.T) {
		eid := uuid.New()
		if _, err := conn.Exec(ctx, `
			INSERT INTO uptime.audit_events
			  (id,actor_id,actor_kind,action,subject_type,subject_id,
			   reason,outcome,request_id)
			VALUES ($1,$2,'USER','users:suspend','user',$3,
			   'drill evidence','SUCCESS','dq-audit-1')`,
			eid, sec.UserID, viewer.UserID.String()); err != nil {
			t.Fatal(err)
		}
		defer func() {
			c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, _ = conn.Exec(c,
				`DELETE FROM uptime.audit_events WHERE id=$1`, eid)
		}()

		a, err := admin.GetAuditEvent(ctx, conn, sec, eid, now)
		if err != nil {
			t.Fatalf("secadmin GetAuditEvent: %v", err)
		}
		if a.ID != eid || a.Action != "users:suspend" || a.Outcome != "SUCCESS" {
			t.Fatalf("wrong row %+v", a)
		}
		if _, err := admin.GetAuditEvent(ctx, conn, viewer, eid, now); !errors.Is(err, admin.ErrForbidden) {
			t.Fatalf("viewer must be denied, got %v", err)
		}
		if _, err := admin.GetAuditEvent(ctx, conn, sec, uuid.New(), now); !errors.Is(err, admin.ErrSubjectRevoked) {
			t.Fatalf("missing id must be 404-ish, got %v", err)
		}
	})

	t.Run("ListRoleCatalog returns presets + ceiling under roles:read", func(t *testing.T) {
		cat, err := admin.ListRoleCatalog(ctx, conn, sec, now)
		if err != nil {
			t.Fatalf("secadmin ListRoleCatalog: %v", err)
		}
		if len(cat.Roles) < 5 || len(cat.Catalog) == 0 {
			t.Fatalf("incomplete catalog %+v", cat)
		}
		var sawViewer, sawPerm bool
		for _, r := range cat.Roles {
			if r.Code == "VIEWER" {
				sawViewer = r.IsPreset
			}
		}
		for _, p := range cat.Catalog {
			if p.ID == "users:read" {
				sawPerm = true
			}
		}
		if !sawViewer || !sawPerm {
			t.Fatalf("missing VIEWER preset or users:read perm: %+v", cat)
		}
		if _, err := admin.ListRoleCatalog(ctx, conn, viewer, now); !errors.Is(err, admin.ErrForbidden) {
			t.Fatalf("viewer must be denied, got %v", err)
		}
	})
}
