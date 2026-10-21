package analytics

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ServiceConfig carries retention + profile policy the read model
// must surface honestly.
type ServiceConfig struct {
	RawRetentionHours    int    // local 720 / hosted-free 24
	HourlyRetentionDays  int    // 30
	Profile              string // "local" | "hosted-free"
}

// Service composes repository reads into the contract projections.
type Service struct {
	repo *Repository
	cfg  ServiceConfig
}

func NewService(repo *Repository, cfg ServiceConfig) *Service {
	return &Service{repo: repo, cfg: cfg}
}

var ErrCursor = errors.New("invalid cursor")

// ------------------------------------------------------------------
// Checks history
// ------------------------------------------------------------------

type ChecksPage struct {
	Checks     []CheckRow
	NextCursor string
	HasMore    bool
}

const checkPageMax = 100
const checkRangeMax = 30 * 24 * time.Hour

// ListChecks validates window/cursor and returns a bounded page.
func (s *Service) ListChecks(ctx context.Context, ownerID, monID uuid.UUID,
	from, to time.Time, cursor string, limit int) (ChecksPage, error) {
	if err := s.repo.OwnMonitor(ctx, ownerID, monID); err != nil {
		return ChecksPage{}, err
	}
	if limit < 1 || limit > checkPageMax {
		limit = 50
	}
	if to.Before(from) || to.Sub(from) > checkRangeMax {
		return ChecksPage{}, fmt.Errorf("%w: range", ErrWindow)
	}
	var at *time.Time
	var id *uuid.UUID
	if cursor != "" {
		c, err := decodeKeyset(cursor, "c1")
		if err != nil {
			return ChecksPage{}, ErrCursor
		}
		at, id = &c.ts, &c.id
	}
	rows, err := s.repo.ListChecks(ctx, monID, from, to, at, id, limit)
	if err != nil {
		return ChecksPage{}, err
	}
	p := ChecksPage{Checks: rows}
	if len(rows) > limit {
		p.Checks = rows[:limit]
		p.HasMore = true
		last := p.Checks[limit-1]
		p.NextCursor = encodeKeyset("c1", last.SlotAt, last.RunID)
	}
	return p, nil
}

// ------------------------------------------------------------------
// Incidents history
// ------------------------------------------------------------------

type IncidentsPage struct {
	Incidents  []IncidentRow
	NextCursor string
	HasMore    bool
}

func (s *Service) ListIncidents(ctx context.Context, ownerID,
	monID uuid.UUID, state, cursor string, limit int) (IncidentsPage, error) {
	if err := s.repo.OwnMonitor(ctx, ownerID, monID); err != nil {
		return IncidentsPage{}, err
	}
	switch state {
	case "", "open", "resolved":
	default:
		return IncidentsPage{}, fmt.Errorf("%w: state", ErrWindow)
	}
	if limit < 1 || limit > checkPageMax {
		limit = 50
	}
	var at *time.Time
	var id *uuid.UUID
	if cursor != "" {
		c, err := decodeKeyset(cursor, "i1")
		if err != nil {
			return IncidentsPage{}, ErrCursor
		}
		at, id = &c.ts, &c.id
	}
	rows, err := s.repo.ListIncidents(ctx, monID, state, at, id, limit)
	if err != nil {
		return IncidentsPage{}, err
	}
	p := IncidentsPage{Incidents: rows}
	if len(rows) > limit {
		p.Incidents = rows[:limit]
		p.HasMore = true
		last := p.Incidents[limit-1]
		p.NextCursor = encodeKeyset("i1", last.OpenedAt, last.ID)
	}
	return p, nil
}

// ------------------------------------------------------------------
// Statistics — the F05 requested/represented window contract
// ------------------------------------------------------------------

var ErrWindow = errors.New("invalid window")

// StatsResult is the per-monitor window projection. Bounds and every
// count share ONE represented interval W_data — the denominator is
// never the requested window while numerators come from retained
// data.
type StatsResult struct {
	WindowStart        time.Time
	WindowEnd          time.Time
	DataStart          *time.Time
	DataEnd            *time.Time
	Counts             SampleCounts
	Expected           int64
	Missed             int64
	Pending            int64
	SampleUptime       *float64
	Coverage           *float64
	MeanDurationMs     *float64
	RawRetentionHours  int
	HourlyRetentionDays int
	RawAvailableFrom   *time.Time
	Resolution         string // "raw" | "hourly" | "mixed" | "none"
	IsPartial          bool
	Series             []BucketPoint
}

// Statistics computes the merged raw+hourly projection for a
// requested window [ws,we). The W_data rules (spec 06, review F05):
//
//   - window bounds keep the request; data bounds are the represented
//     half-open interval — never first/last observed times.
//   - The raw boundary hour is conservative: it may be partially
//     purged, so raw only serves from ceil_hour(earliest retained
//     raw slot). Older coverage comes from complete hourly buckets.
//   - A bucket contributes only when fully inside W_data — its whole
//     hour must lie in the represented interval.
//   - Rolled rows inside uncovered boundary hours are still counted
//     via raw (their bucket was not used) — nothing double-counts and
//     nothing drops.
//   - Nothing representable: null bounds, zero counts, null ratios,
//     empty series, is_partial.
func (s *Service) Statistics(ctx context.Context, ownerID,
	monID uuid.UUID, ws, we, now time.Time) (StatsResult, error) {
	res := StatsResult{
		WindowStart:         ws, WindowEnd: we,
		RawRetentionHours:   s.cfg.RawRetentionHours,
		HourlyRetentionDays: s.cfg.HourlyRetentionDays,
		Resolution:          "none",
	}
	if err := s.repo.OwnMonitor(ctx, ownerID, monID); err != nil {
		return res, err
	}
	if !we.After(ws) {
		return res, fmt.Errorf("%w: empty range", ErrWindow)
	}

	rawFrom, hourFrom, segFrom, err := s.repo.RetentionBounds(ctx, monID)
	if err != nil {
		return res, err
	}
	res.RawAvailableFrom = rawFrom

	// Boundary-hour rule (F05): the hour containing the oldest
	// retained raw slot is suspect — indistinguishable purged vs
	// never-scheduled slots — UNLESS every nominal segment slot in it
	// still has a run, which proves completeness. When suspect, the
	// represented start snaps to the next UTC hour; the boundary
	// hour's bucket cannot substitute because it is not fully inside
	// the truncated interval. When the hour has no bucket, no purge
	// could have removed its raw (retention never purges unrolled
	// data), so raw is complete and the boundary stays exact.
	var earliest time.Time // zero = nothing representable
	if hourFrom != nil && hourFrom.Before(we) {
		earliest = *hourFrom
	}
	if rawFrom != nil && rawFrom.Before(we) {
		h0 := floorHour(*rawFrom)
		edge := *rawFrom
		if hasBucket, bErr := s.repo.BucketAt(ctx, monID, h0); bErr != nil {
			return res, bErr
		} else if hasBucket {
			// Purge reached this hour at some point — it is exact
			// only if every nominal slot still has a run.
			exp, eErr := s.repo.ExpectedSlots(ctx, monID, h0,
				h0.Add(time.Hour))
			runs, rErr := s.repo.RunsInRange(ctx, monID, h0,
				h0.Add(time.Hour))
			if eErr != nil {
				return res, eErr
			}
			if rErr != nil {
				return res, rErr
			}
			if exp > runs {
				edge = h0.Add(time.Hour)
			}
		}
		if earliest.IsZero() || edge.Before(earliest) {
			earliest = edge
		}
	}
	// Schedule segments are durable denominator evidence: the window
	// remains representable (as all-missed) even when every run was
	// purged. Only a window that intersects NO retained evidence and
	// NO segment is unrepresentable.
	if segFrom != nil && segFrom.Before(we) {
		if earliest.IsZero() || segFrom.Before(earliest) {
			earliest = *segFrom
		}
	}

	// The represented start is the LATER of the requested edge and
	// the first representable instant — the only normalizations that
	// exist. A suspect boundary hour already arrives hour-aligned;
	// a provably complete raw edge stays exact (raw suffices to cut
	// the partial boundary hour by nominal slot).
	if earliest.IsZero() {
		res.IsPartial = true
		return res, nil
	}
	ds := maxTime(ws, earliest)
	if !ds.Before(we) {
		res.IsPartial = true
		return res, nil
	}
	de := we
	res.DataStart, res.DataEnd = &ds, &de
	res.IsPartial = ds.After(ws) || (rawFrom == nil && hourFrom == nil)

	// Disjoint merge: complete buckets + uncovered raw.
	hc, err := s.repo.HourlyCounts(ctx, monID, ds, de)
	if err != nil {
		return res, err
	}
	rc, err := s.repo.RawCounts(ctx, monID, ds, de)
	if err != nil {
		return res, err
	}
	res.Counts = MergeSampleCounts(hc, rc)
	switch {
	case hc.Valid+hc.Excluded > 0 && rc.Valid+rc.Excluded > 0:
		res.Resolution = "mixed"
	case hc.Valid+hc.Excluded > 0:
		res.Resolution = "hourly"
	case rc.Valid+rc.Excluded > 0:
		res.Resolution = "raw"
	}

	// Expected counts nominal slots the segment schedule owed — the
	// denominator never trusts current data completeness. Future slots
	// are not owed yet: clamp at now.
	expEnd := de
	if now.Before(de) {
		expEnd = now
	}
	if expEnd.After(ds) {
		if res.Expected, err = s.repo.ExpectedSlots(ctx, monID, ds, expEnd); err != nil {
			return res, err
		}
		if res.Pending, err = s.repo.PendingSlots(ctx, monID, ds, expEnd); err != nil {
			return res, err
		}
	}
	res.Missed = res.Expected - res.Counts.Valid - res.Counts.Excluded - res.Pending
	if res.Missed < 0 {
		res.Missed = 0 // defensive: identity must never go negative
	}
	res.SampleUptime = SampleUptime(res.Counts)
	res.MeanDurationMs = MeanDurationMs(res.Counts)
	if res.Expected > 0 {
		c := float64(res.Counts.Valid) / float64(res.Expected)
		res.Coverage = &c
	}
	res.Series, err = s.repo.Series(ctx, monID, ds, de)
	return res, err
}

// ------------------------------------------------------------------
// Dashboard summary
// ------------------------------------------------------------------

type Quota struct {
	Used    int64     `json:"used"`
	Active  int64     `json:"active"`
	Paused  int64     `json:"paused"`
	Limit   int64     `json:"limit"`
	Profile string    `json:"profile"`
	AsOf    time.Time `json:"as_of"`
	Source  string    `json:"source"`
}

type Dashboard struct {
	Monitors       int64
	Active         int64
	Paused         int64
	Up             int64
	Down           int64
	OpenIncidents  int64
	RecentIncidents []IncidentListRow
	SampleUptime24h *float64
	Quota          Quota
	AsOf           time.Time
}

func (s *Service) Dashboard(ctx context.Context,
	ownerID uuid.UUID, now time.Time) (Dashboard, error) {
	var d Dashboard
	sum, err := s.repo.DashboardSummary(ctx, ownerID,
		now.Add(-24*time.Hour))
	if err != nil {
		return d, err
	}
	d.Monitors, d.Active, d.Paused = sum.Monitors, sum.Active, sum.Paused
	d.Up, d.Down, d.OpenIncidents = sum.Up, sum.Down, sum.OpenIncidents
	if sum.Valid24h > 0 {
		v := float64(sum.Success24h) / float64(sum.Valid24h)
		d.SampleUptime24h = &v
	}
	d.RecentIncidents, err = s.repo.RecentIncidents(ctx, ownerID, 10)
	if err != nil {
		return d, err
	}
	d.AsOf = now.UTC()
	d.Quota = Quota{
		Used:    sum.Monitors,
		Active:  sum.Active,
		Paused:  sum.Paused,
		Limit:   sum.MonitorLimit,
		Profile: s.cfg.Profile,
		AsOf:    d.AsOf,
		Source:  "server",
	}
	return d, nil
}

// ------------------------------------------------------------------
// keyset cursors — opaque, versioned, unbounded-length guarded
// ------------------------------------------------------------------

type keyset struct {
	ts time.Time
	id uuid.UUID
}

type keysetJSON struct {
	TS int64  `json:"ts"`
	ID string `json:"id"`
}

func encodeKeyset(ver string, ts time.Time, id uuid.UUID) string {
	b, _ := json.Marshal(keysetJSON{TS: ts.UTC().UnixNano(), ID: id.String()})
	return ver + "." + base64.RawURLEncoding.EncodeToString(b)
}

func decodeKeyset(s, ver string) (keyset, error) {
	var k keyset
	if len(s) > 512 || !strings.HasPrefix(s, ver+".") {
		return k, ErrCursor
	}
	b, err := base64.RawURLEncoding.DecodeString(s[len(ver)+1:])
	if err != nil {
		return k, ErrCursor
	}
	var j keysetJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return k, ErrCursor
	}
	k.ts = time.Unix(0, j.TS).UTC()
	k.id, err = uuid.Parse(j.ID)
	return k, err
}

func floorHour(t time.Time) time.Time {
	u := t.UTC()
	return time.Date(u.Year(), u.Month(), u.Day(), u.Hour(), 0, 0, 0,
		time.UTC)
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
