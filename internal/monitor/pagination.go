package monitor

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Cursors are UNTRUSTED client data. They carry a keyset position and
// a fingerprint of the filter set they were issued under — never an
// owner id: ownership comes from the session, and a foreign cursor
// simply pages the caller's own rows from a position it can't reach.
//
// Format: m1.<base64url(json{ts,id,fp})>. The version prefix makes a
// future format change a clean rejection instead of silent mispage.
// Bounded length keeps a junk cursor from becoming an oversized query.

const (
	cursorVersion = "m1"
	maxCursorLen  = 512
	maxSearchLen  = 120
	maxPageLimit  = 100
	defPageLimit  = 20
)

// ErrCursor is the single rejection reason — details go to the
// client only as a generic 400, never an internal 500.
var ErrCursor = errors.New("invalid cursor")

// ListFilter is the bounded filter set for the collection route.
// Zero values mean "no filter". Search is an escaped ILIKE substring
// on name — wildcards can never reach the query unescaped.
type ListFilter struct {
	Paused *bool
	Health string // "", UNKNOWN, UP, DOWN
	Search string // "" or substring, length-bounded
}

// PageRequest is the validated query state for one listing call.
type PageRequest struct {
	Limit  int
	Filter ListFilter
	After  Cursor
}

// ParsePageRequest validates raw query values into a PageRequest.
// Every rejection is a FieldError keyed on the offending parameter.
func ParsePageRequest(q map[string][]string) (PageRequest, error) {
	var (
		out PageRequest
		f   = map[string]string{}
	)
	out.Limit = defPageLimit
	if v := first(q, "limit"); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err != nil || n < 1 || n > maxPageLimit {
			f["limit"] = fmt.Sprintf("must be 1..%d", maxPageLimit)
		} else {
			out.Limit = n
		}
	}
	if v := first(q, "paused"); v != "" {
		switch v {
		case "true":
			b := true
			out.Filter.Paused = &b
		case "false":
			b := false
			out.Filter.Paused = &b
		default:
			f["paused"] = "must be true or false"
		}
	}
	if v := first(q, "health"); v != "" {
		switch v {
		case HealthUnknown, HealthUp, HealthDown:
			out.Filter.Health = v
		default:
			f["health"] = "must be UNKNOWN, UP, or DOWN"
		}
	}
	if v := first(q, "q"); v != "" {
		if len(v) > maxSearchLen {
			f["q"] = fmt.Sprintf("must be at most %d characters", maxSearchLen)
		} else {
			out.Filter.Search = v
		}
	}
	var cursorErr error
	if v := first(q, "cursor"); v != "" {
		c, err := DecodeCursor(v, out.Filter)
		if err != nil {
			cursorErr = err
		} else {
			out.After = c
		}
	}
	if len(f) > 0 {
		return PageRequest{}, fe(f)
	}
	if cursorErr != nil {
		// Cursor failures are a 400 (card contract) — never folded
		// into the 422 validation map.
		return PageRequest{}, ErrCursor
	}
	return out, nil
}

func first(q map[string][]string, k string) string {
	if vs := q[k]; len(vs) > 0 {
		return vs[0]
	}
	return ""
}

// filterFingerprint binds a cursor to the exact filter set it was
// issued under — resuming with different filters is a 400, not a
// silently re-scoped page (filter swaps would skip/dup rows).
func filterFingerprint(f ListFilter) string {
	paused := "any"
	if f.Paused != nil {
		if *f.Paused {
			paused = "1"
		} else {
			paused = "0"
		}
	}
	sum := sha256.Sum256([]byte(paused + "|" + f.Health + "|" + f.Search))
	return hex.EncodeToString(sum[:8])
}

type cursorJSON struct {
	TS int64  `json:"ts"`
	ID string `json:"id"`
	FP string `json:"fp"`
}

// EncodeCursor renders the opaque resume token for the last row of
// the returned page under the current filter set.
func EncodeCursor(last Monitor, f ListFilter) string {
	payload, _ := json.Marshal(cursorJSON{
		TS: last.CreatedAt.UTC().UnixNano(),
		ID: last.ID.String(),
		FP: filterFingerprint(f),
	})
	return cursorVersion + "." + base64.RawURLEncoding.EncodeToString(payload)
}

// DecodeCursor validates and parses a client-supplied cursor against
// the CURRENT filter set. Malformed, foreign-version, oversized, or
// filter-mismatched cursors all collapse to ErrCursor.
func DecodeCursor(s string, f ListFilter) (Cursor, error) {
	if len(s) > maxCursorLen || !strings.HasPrefix(s, cursorVersion+".") {
		return Cursor{}, ErrCursor
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, cursorVersion+"."))
	if err != nil || len(raw) > maxCursorLen {
		return Cursor{}, ErrCursor
	}
	var cj cursorJSON
	if err := json.Unmarshal(raw, &cj); err != nil {
		return Cursor{}, ErrCursor
	}
	id, err := uuid.Parse(cj.ID)
	if err != nil || cj.TS <= 0 {
		return Cursor{}, ErrCursor
	}
	if cj.FP != filterFingerprint(f) {
		return Cursor{}, ErrCursor
	}
	return Cursor{CreatedAt: time.Unix(0, cj.TS).UTC(), ID: id, Valid: true}, nil
}
