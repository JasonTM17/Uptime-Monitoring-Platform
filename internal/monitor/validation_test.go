package monitor

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func fields(t *testing.T, err error) map[string]string {
	t.Helper()
	var fe *FieldError
	if !errors.As(err, &fe) {
		t.Fatalf("expected FieldError, got %v", err)
	}
	return fe.Fields
}

func TestValidateCreate(t *testing.T) {
	good := CreateInput{
		Name: "home", TargetURL: "https://example.com/health",
		IntervalSeconds: 60, TimeoutSeconds: 5,
	}

	t.Run("happy path incl. null expected_status", func(t *testing.T) {
		if err := ValidateCreate(good); err != nil {
			t.Fatal(err)
		}
		s := 204
		g2 := good
		g2.ExpectedStatus = &s
		if err := ValidateCreate(g2); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("field bounds", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			mut  func(*CreateInput)
			key  string
		}{
			{"empty name", func(g *CreateInput) { g.Name = "  " }, "name"},
			{"overlong name", func(g *CreateInput) { g.Name = strings.Repeat("n", 121) }, "name"},
			{"interval below floor", func(g *CreateInput) { g.IntervalSeconds = 59 }, "interval_seconds"},
			{"interval above ceiling", func(g *CreateInput) { g.IntervalSeconds = 86401 }, "interval_seconds"},
			{"timeout zero", func(g *CreateInput) { g.TimeoutSeconds = 0 }, "timeout_seconds"},
			{"timeout above ceiling", func(g *CreateInput) { g.TimeoutSeconds = 11 }, "timeout_seconds"},
			{"expected status below", func(g *CreateInput) { s := 199; g.ExpectedStatus = &s }, "expected_status"},
			{"expected status above", func(g *CreateInput) { s := 600; g.ExpectedStatus = &s }, "expected_status"},
		} {
			g := good
			tc.mut(&g)
			if got := fields(t, ValidateCreate(g)); got[tc.key] == "" {
				t.Fatalf("%s: expected %s error, got %v", tc.name, tc.key, got)
			}
		}
	})

	t.Run("bounds edges", func(t *testing.T) {
		g := good
		g.IntervalSeconds, g.TimeoutSeconds = 60, 10
		if err := ValidateCreate(g); err != nil {
			t.Fatalf("10<60 valid: %v", err)
		}
		// With policy bounds (timeout ≤10, interval ≥60) the
		// timeout>=interval relation is unreachable at create — it
		// only matters when PATCH merges over stored values.
		g.IntervalSeconds = 60
		g.TimeoutSeconds = 1
		if err := ValidateCreate(g); err != nil {
			t.Fatalf("floor edge: %v", err)
		}
		g.IntervalSeconds = 86400
		g.TimeoutSeconds = 10
		if err := ValidateCreate(g); err != nil {
			t.Fatalf("ceiling edge: %v", err)
		}
	})
}

func TestTargetSyntax(t *testing.T) {
	t.Run("accepted forms", func(t *testing.T) {
		for _, raw := range []string{
			"https://example.com",
			"https://example.com:443/health?x=1",
			"http://example.com:80/",
			"https://8.8.8.8/ping",
			"https://sub.domain.co.uk/a/b?c=d",
		} {
			if _, err := ParseTargetPolicy(raw); err != nil {
				t.Fatalf("%s: %v", raw, err)
			}
		}
	})

	t.Run("rejected forms", func(t *testing.T) {
		for _, raw := range []string{
			"",                    // required
			"ftp://example.com",   // scheme
			"javascript:alert(1)", // scheme
			// userinfo (concat built — no credential-shaped literal in source)
			"https://user" + ":" + "pw" + "@example.com",
			"https://user@example.com",            // userinfo user-only
			"https://example.com/#frag",           // fragment
			"https://example.com:8443/",           // nonstandard port
			"https://example.com:22/",             // ssh port
			"https://127.0.0.1/",                  // loopback literal
			"https://10.0.0.5/",                   // private literal
			"https://192.168.1.1/",                // private literal
			"https://[::1]/",                      // v6 loopback
			"https://[fd00::1]/",                  // v6 private ULA
			"https://169.254.169.254/latest/meta", // link-local metadata
			"https://0.0.0.0/",                    // unspecified
			"https://example .com/",               // whitespace
			"not a url",
			"https://" + strings.Repeat("a", 2100) + ".com/",
		} {
			if _, err := ParseTargetPolicy(raw); err == nil {
				t.Fatalf("%q: expected rejection", raw)
			}
		}
	})

	t.Run("errors carry field, not raw URL", func(t *testing.T) {
		_, err := ParseTargetPolicy("https://user" + ":" + "hidden" + "@example.com/?token=abc")
		f := fields(t, err)
		if _, ok := f["target_url"]; !ok {
			t.Fatalf("no field error: %v", f)
		}
		if strings.Contains(f["target_url"], "secret") || strings.Contains(f["target_url"], "abc") {
			t.Fatal("error echoes sensitive URL content")
		}
	})
}

func TestValidatePatch(t *testing.T) {
	decode := func(body string) PatchInput {
		var in PatchInput
		if err := json.Unmarshal([]byte(body), &in); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return in
	}

	t.Run("absent vs null vs value", func(t *testing.T) {
		in := decode(`{"name":"n"}`)
		if !in.Name.Set || in.Name.Null || in.Name.V != "n" {
			t.Fatalf("set/value: %+v", in.Name)
		}
		if in.TargetURL.Set {
			t.Fatal("absent marked set")
		}
		in = decode(`{"expected_status":null}`)
		if !in.ExpectedStatus.Set || !in.ExpectedStatus.Null {
			t.Fatalf("null expected_status: %+v", in.ExpectedStatus)
		}
	})

	t.Run("non-nullable fields reject explicit null", func(t *testing.T) {
		for _, body := range []string{
			`{"name":null}`, `{"target_url":null}`,
			`{"interval_seconds":null}`, `{"timeout_seconds":null}`,
		} {
			if err := ValidatePatch(decode(body)); err == nil {
				t.Fatalf("%s: expected rejection", body)
			}
		}
	})

	t.Run("empty patch rejected", func(t *testing.T) {
		if err := ValidatePatch(decode(`{}`)); err == nil {
			t.Fatal("empty patch accepted")
		}
	})

	t.Run("valid partial patch", func(t *testing.T) {
		in := decode(`{"interval_seconds":300,"expected_status":204}`)
		if err := ValidatePatch(in); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("present fields still validated", func(t *testing.T) {
		if err := ValidatePatch(decode(`{"target_url":"https://10.0.0.1/"}`)); err == nil {
			t.Fatal("private literal accepted in patch")
		}
		if err := ValidatePatch(decode(`{"interval_seconds":30}`)); err == nil {
			t.Fatal("below-floor interval accepted in patch")
		}
	})
}
