package checker

import (
	"encoding/json"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

// destinationFixture is the C27 oracle: independently captured
// expectations for the destination policy. Assertions against the
// implementation land in C28 — THIS file only proves the oracle is
// well-formed, complete, and self-consistent.
type destinationFixture struct {
	Schema   string `json:"schema"`
	Captured string `json:"captured"`
	Sources  []struct {
		Name string `json:"name"`
		URL  string `json:"url"`
		AsOf string `json:"as_of"`
	} `json:"sources"`
	AddressCases []struct {
		ID       string `json:"id"`
		Input    string `json:"input"`
		Category string `json:"category"`
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	} `json:"address_cases"`
	URLCases []struct {
		ID       string `json:"id"`
		Input    string `json:"input"`
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	} `json:"url_cases"`
}

func loadDestinationFixture(t *testing.T) destinationFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "destination-policy.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var f destinationFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("fixture is not valid JSON: %v", err)
	}
	return f
}

func TestDestinationFixtureIntegrity(t *testing.T) {
	f := loadDestinationFixture(t)
	if f.Schema != "destination-policy/v1" {
		t.Fatalf("unknown schema %q", f.Schema)
	}
	if f.Captured == "" || len(f.Sources) < 2 {
		t.Fatal("fixture must declare capture date and at least two independent sources")
	}
	for _, s := range f.Sources {
		if s.Name == "" || s.URL == "" || s.AsOf == "" {
			t.Errorf("source missing name/url/date: %+v", s)
		}
	}

	seen := map[string]bool{}
	for _, c := range f.AddressCases {
		if c.ID == "" || c.Reason == "" {
			t.Errorf("case missing id/reason: %+v", c)
		}
		if seen[c.ID] {
			t.Errorf("duplicate case id %q", c.ID)
		}
		seen[c.ID] = true
		switch c.Decision {
		case "allow", "deny":
		default:
			t.Errorf("%s: bad decision %q", c.ID, c.Decision)
		}
		// Every address input must parse as netip.Addr (with or
		// without zone) — a malformed input is a broken oracle.
		addr, err := netip.ParseAddr(c.Input)
		if err != nil {
			t.Errorf("%s: input %q does not parse as an address: %v", c.ID, c.Input, err)
			continue
		}
		// A public/allow expectation on an obviously non-unicast
		// address would corrupt the whole oracle — sanity check the
		// two free signals (not a reimplementation of the policy).
		if c.Decision == "deny" && (addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast()) {
			continue // consistent with the obvious property
		}
		if c.Decision == "allow" && (addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalUnicast()) {
			t.Errorf("%s: allows an address that is loopback/unspecified/multicast/link-local (%s)", c.ID, c.Input)
		}
	}
	for _, c := range f.URLCases {
		if c.ID == "" || c.Reason == "" {
			t.Errorf("url case missing id/reason: %+v", c)
		}
		if seen[c.ID] {
			t.Errorf("duplicate case id %q", c.ID)
		}
		seen[c.ID] = true
		switch c.Decision {
		case "allow", "deny":
		default:
			t.Errorf("%s: bad decision %q", c.ID, c.Decision)
		}
		if _, err := url.Parse(c.Input); err != nil {
			t.Errorf("%s: input %q is not parseable at all: %v", c.ID, c.Input, err)
		}
	}
}

func TestDestinationFixtureCoverage(t *testing.T) {
	f := loadDestinationFixture(t)
	want := []string{
		"loopback", "private", "link-local", "cgnat", "unspecified",
		"multicast", "documentation", "reserved", "mapped-v6",
		"zone-id", "public",
	}
	have := map[string]int{}
	allows, denies := 0, 0
	for _, c := range f.AddressCases {
		have[c.Category]++
		if c.Decision == "allow" {
			allows++
		} else {
			denies++
		}
	}
	for _, cat := range want {
		if have[cat] == 0 {
			t.Errorf("no fixture cases for category %q", cat)
		}
	}
	if allows < 3 {
		t.Errorf("need at least 3 positive public controls, have %d", allows)
	}
	if denies < 10 {
		t.Errorf("need at least 10 denied cases, have %d", denies)
	}
	if len(f.URLCases) < 8 {
		t.Errorf("url_cases too thin: %d", len(f.URLCases))
	}
}
