//go:build integration

package monitor_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

var ctxBg = context.Background()

type page struct {
	Items      []map[string]any `json:"items"`
	HasMore    bool             `json:"has_more"`
	NextCursor *string          `json:"next_cursor"`
}

func (c *monClient) page(t *testing.T, query string) (int, page) {
	t.Helper()
	rec := c.do(http.MethodGet, "/monitors"+query, "", false)
	var env struct {
		Data page `json:"data"`
	}
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("decode page: %v", err)
		}
	}
	return rec.Code, env.Data
}

func TestMonitorPagination(t *testing.T) {
	f := newMonFixture(t)
	defer f.cleanup()
	a := f.newClient()
	a.join(f.email("pg"))

	ids := map[string]bool{}
	for i := 0; i < 5; i++ {
		m := a.create(fmt.Sprintf("pg-%d", i))
		ids[m["id"].(string)] = true
	}

	t.Run("three stable pages, no duplicates, has_more honest", func(t *testing.T) {
		seen := map[string]bool{}
		cursor := ""
		pages := 0
		for {
			code, pg := a.page(t, "?limit=2"+cursor)
			if code != http.StatusOK {
				t.Fatalf("page %d: %d", pages, code)
			}
			pages++
			if len(pg.Items) > 2 {
				t.Fatalf("page returned %d items > limit", len(pg.Items))
			}
			for _, it := range pg.Items {
				id := it["id"].(string)
				if seen[id] {
					t.Fatalf("duplicate across pages: %s", id)
				}
				seen[id] = true
			}
			if !pg.HasMore {
				if pg.NextCursor != nil {
					t.Fatal("next_cursor set on last page")
				}
				break
			}
			if pg.NextCursor == nil {
				t.Fatal("has_more without cursor")
			}
			cursor = "&cursor=" + *pg.NextCursor
			if pages > 10 {
				t.Fatal("pagination did not terminate")
			}
		}
		if len(seen) != 5 {
			t.Fatalf("saw %d of 5 monitors", len(seen))
		}
	})

	t.Run("newest-first ordering within a page", func(t *testing.T) {
		_, pg := a.page(t, "?limit=5")
		prev := ""
		for _, it := range pg.Items {
			ts := it["created_at"].(string)
			if prev != "" && ts > prev {
				t.Fatalf("order not newest-first: %v", pg.Items)
			}
			prev = ts
		}
	})

	t.Run("paused filter narrows without leaking others", func(t *testing.T) {
		// Pause one monitor via SQL (the API pause lands in C23 —
		// the filter test only needs a paused row to exist).
		_, pg := a.page(t, "?limit=1")
		firstID := pg.Items[0]["id"].(string)
		if _, err := f.pool.Exec(ctxBg,
			`UPDATE uptime.monitors SET is_paused=true WHERE id=$1`, firstID); err != nil {
			t.Fatal(err)
		}
		code, pg := a.page(t, "?limit=10&paused=true")
		if code != http.StatusOK || len(pg.Items) != 1 || pg.Items[0]["id"] != firstID {
			t.Fatalf("paused filter: %d %+v", code, pg.Items)
		}
		code, pg = a.page(t, "?limit=10&paused=false")
		if code != http.StatusOK || len(pg.Items) != 4 {
			t.Fatalf("unpaused filter: %d items", len(pg.Items))
		}
	})

	t.Run("search is escaped substring on name", func(t *testing.T) {
		code, pg := a.page(t, "?limit=10&q=pg-1")
		if code != http.StatusOK || len(pg.Items) != 1 {
			t.Fatalf("search: %d items %v", code, pg.Items)
		}
		// Wildcard chars must NOT widen — % searches literally.
		code, pg = a.page(t, "?limit=10&q=%25")
		if code != http.StatusOK || len(pg.Items) != 0 {
			t.Fatalf("wildcard search leaked %d items", len(pg.Items))
		}
	})

	t.Run("cursor bound to filter set — swap -> 400", func(t *testing.T) {
		_, pg := a.page(t, "?limit=2&paused=false")
		if pg.NextCursor == nil {
			t.Skip("need a filtered second page")
		}
		code, _ := a.page(t, "?limit=2&paused=true&cursor="+*pg.NextCursor)
		if code != http.StatusBadRequest {
			t.Fatalf("filter-swapped cursor: %d", code)
		}
	})

	t.Run("malformed cursor -> 400, garbage limit -> 422", func(t *testing.T) {
		if code, _ := a.page(t, "?cursor=junk"); code != http.StatusBadRequest {
			t.Fatalf("bad cursor %d", code)
		}
		if code, _ := a.page(t, "?limit=abc"); code != http.StatusUnprocessableEntity {
			t.Fatalf("bad limit %d", code)
		}
		if code, _ := a.page(t, "?limit=0"); code != http.StatusUnprocessableEntity {
			t.Fatalf("zero limit %d", code)
		}
	})
}

func TestPaginationIsolation(t *testing.T) {
	f := newMonFixture(t)
	defer f.cleanup()
	a, b := f.newClient(), f.newClient()
	a.join(f.email("pg-a"))
	b.join(f.email("pg-b"))

	m := b.create("b-only")
	bID := m["id"].(string)
	b.create("b-two") // second row so B earns a real cursor
	for i := 0; i < 3; i++ {
		a.create(fmt.Sprintf("a-%d", i))
	}

	// A's pages contain only A's rows — B's existence is invisible.
	cursor := ""
	for i := 0; i < 10; i++ {
		code, pg := a.page(t, "?limit=2"+cursor)
		if code != http.StatusOK {
			t.Fatalf("page %d", code)
		}
		for _, it := range pg.Items {
			if it["id"] == bID {
				t.Fatal("foreign monitor leaked into page")
			}
		}
		if !pg.HasMore {
			break
		}
		cursor = "&cursor=" + *pg.NextCursor
	}

	// B's cursor issued under B's session never helps A reach B's
	// data — resuming with it just pages A's own rows.
	_, bpg := b.page(t, "?limit=1")
	if bpg.NextCursor != nil {
		code, pg := a.page(t, "?limit=1&cursor="+*bpg.NextCursor)
		if code != http.StatusOK {
			t.Fatalf("foreign cursor rejected with %d — should page own rows", code)
		}
		for _, it := range pg.Items {
			if it["id"] == bID {
				t.Fatal("foreign cursor reached B's data")
			}
		}
	}
}
