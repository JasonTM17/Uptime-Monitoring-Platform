package monitor

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCursor(t *testing.T) {
	filt := ListFilter{}
	m := Monitor{ID: uuid.New(), CreatedAt: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}

	t.Run("roundtrip preserves position", func(t *testing.T) {
		tok := EncodeCursor(m, filt)
		c, err := DecodeCursor(tok, filt)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !c.Valid || c.ID != m.ID || !c.CreatedAt.Equal(m.CreatedAt) {
			t.Fatalf("roundtrip mismatch %+v", c)
		}
	})

	t.Run("wrong version rejected", func(t *testing.T) {
		tok := EncodeCursor(m, filt)
		if _, err := DecodeCursor("v2"+tok[2:], filt); !errors.Is(err, ErrCursor) {
			t.Fatalf("want ErrCursor, got %v", err)
		}
	})

	t.Run("malformed payloads rejected", func(t *testing.T) {
		for _, tok := range []string{
			"", "not-a-cursor", "m1.%%%", "m1.e30",
			"m1." + strings.Repeat("A", 4096),
		} {
			if _, err := DecodeCursor(tok, filt); !errors.Is(err, ErrCursor) {
				t.Fatalf("token %q: want ErrCursor, got %v", tok[:min(20, len(tok))], err)
			}
		}
	})

	t.Run("oversized cursor rejected before decode", func(t *testing.T) {
		if _, err := DecodeCursor(cursorVersion+"."+strings.Repeat("x", maxCursorLen+1), filt); !errors.Is(err, ErrCursor) {
			t.Fatal("oversized accepted")
		}
	})

	t.Run("filter mismatch rejected", func(t *testing.T) {
		paused := true
		other := ListFilter{Paused: &paused}
		tok := EncodeCursor(m, filt)
		if _, err := DecodeCursor(tok, other); !errors.Is(err, ErrCursor) {
			t.Fatalf("filter-mismatched cursor accepted: %v", err)
		}
		// Same filter still works.
		if _, err := DecodeCursor(tok, filt); err != nil {
			t.Fatalf("same-filter rejected: %v", err)
		}
	})

	t.Run("cursor carries no owner id", func(t *testing.T) {
		tok := EncodeCursor(m, filt)
		owner := uuid.New()
		if strings.Contains(tok, owner.String()) {
			t.Fatal("cursor leaks owner")
		}
	})
}

func TestParsePageRequest(t *testing.T) {
	t.Run("defaults: limit 20, no filters, no cursor", func(t *testing.T) {
		pr, err := ParsePageRequest(map[string][]string{})
		if err != nil || pr.Limit != 20 || pr.Filter.Paused != nil || pr.After.Valid {
			t.Fatalf("%+v %v", pr, err)
		}
	})
	t.Run("bounded limit + filters parse", func(t *testing.T) {
		pr, err := ParsePageRequest(map[string][]string{
			"limit": {"5"}, "paused": {"true"}, "health": {"UP"}, "q": {"api"},
		})
		if err != nil || pr.Limit != 5 || pr.Filter.Paused == nil || !*pr.Filter.Paused ||
			pr.Filter.Health != "UP" || pr.Filter.Search != "api" {
			t.Fatalf("%+v %v", pr, err)
		}
	})
	t.Run("invalid params -> FieldError (422), not panic", func(t *testing.T) {
		_, err := ParsePageRequest(map[string][]string{
			"limit": {"9999"}, "paused": {"maybe"}, "health": {"SICK"},
		})
		var feErr *FieldError
		if !errors.As(err, &feErr) || len(feErr.Fields) != 3 {
			t.Fatalf("want 3 field errors, got %v", err)
		}
	})
	t.Run("bad cursor -> ErrCursor (400)", func(t *testing.T) {
		_, err := ParsePageRequest(map[string][]string{"cursor": {"junk"}})
		if !errors.Is(err, ErrCursor) {
			t.Fatalf("want ErrCursor, got %v", err)
		}
	})
	t.Run("escaped LIKE wildcard stays literal", func(t *testing.T) {
		if got := escapeLike(`100%_`); got != `100\%\_` {
			t.Fatalf("escapeLike = %q", got)
		}
	})
}
