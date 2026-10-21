package monitor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// Validation is SYNTAX-ONLY: parsing proves the policy shape is
// well-formed — it proves NOTHING about the destination. Private-IP
// literals are rejected here as defense-in-depth, but DNS-resolved
// targets are only proven safe at actual-dial time (C28–C31). No
// network I/O ever happens in this file.

const (
	minIntervalSeconds = 60
	maxIntervalSeconds = 86400
	minTimeoutSeconds  = 1
	maxTimeoutSeconds  = 10
	maxNameRunes       = 120
	maxURLBytes        = 2048
)

// FieldError carries per-field validation failures for the
// VALIDATION_ERROR envelope — messages never echo rejected values.
type FieldError struct {
	Fields map[string]string
}

func (e *FieldError) Error() string { return "validation failed" }

func fe(fields map[string]string) *FieldError { return &FieldError{Fields: fields} }

// CreateInput is the exact accepted create body (strict decoder
// rejects every other key — owner/health/generation injection is 400).
type CreateInput struct {
	Name            string `json:"name"`
	TargetURL       string `json:"target_url"`
	IntervalSeconds int    `json:"interval_seconds"`
	TimeoutSeconds  int    `json:"timeout_seconds"`
	ExpectedStatus  *int   `json:"expected_status"`
}

// PatchField distinguishes absent (Set=false) from explicit null
// (Set=true, Null=true) — the PATCH contract needs all three states.
type PatchField[T any] struct {
	Set  bool
	Null bool
	V    T
}

func (p *PatchField[T]) UnmarshalJSON(b []byte) error {
	p.Set = true
	if bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		p.Null = true
		return nil
	}
	return json.Unmarshal(b, &p.V)
}

// PatchInput is the accepted patch body. Non-nullable fields reject
// explicit null; expected_status accepts null (clears to default).
type PatchInput struct {
	Name            PatchField[string] `json:"name"`
	TargetURL       PatchField[string] `json:"target_url"`
	IntervalSeconds PatchField[int]    `json:"interval_seconds"`
	TimeoutSeconds  PatchField[int]    `json:"timeout_seconds"`
	ExpectedStatus  PatchField[int]    `json:"expected_status"`
}

// ValidateCreate checks a create body. Input is never mutated.
func ValidateCreate(in CreateInput) error {
	f := map[string]string{}
	checkName(f, "name", in.Name)
	checkURL(f, "target_url", in.TargetURL)
	checkPolicy(f, in.IntervalSeconds, in.TimeoutSeconds, in.ExpectedStatus)
	if len(f) > 0 {
		return fe(f)
	}
	return nil
}

// ValidatePatch checks a patch body: every present field is valid,
// non-nullable fields reject null, and at least one field is set.
// Field RELATIONS (timeout<interval) are re-checked at the service
// layer against the merged result — the patch alone can't know the
// stored values.
func ValidatePatch(in PatchInput) error {
	f := map[string]string{}
	set := 0
	if in.Name.Set {
		set++
		if in.Name.Null {
			f["name"] = "must not be null"
		} else {
			checkName(f, "name", in.Name.V)
		}
	}
	if in.TargetURL.Set {
		set++
		if in.TargetURL.Null {
			f["target_url"] = "must not be null"
		} else {
			checkURL(f, "target_url", in.TargetURL.V)
		}
	}
	if in.IntervalSeconds.Set {
		set++
		if in.IntervalSeconds.Null {
			f["interval_seconds"] = "must not be null"
		} else if in.IntervalSeconds.V < minIntervalSeconds ||
			in.IntervalSeconds.V > maxIntervalSeconds {
			f["interval_seconds"] = fmt.Sprintf("must be %d..%d",
				minIntervalSeconds, maxIntervalSeconds)
		}
	}
	if in.TimeoutSeconds.Set {
		set++
		if in.TimeoutSeconds.Null {
			f["timeout_seconds"] = "must not be null"
		} else if in.TimeoutSeconds.V < minTimeoutSeconds ||
			in.TimeoutSeconds.V > maxTimeoutSeconds {
			f["timeout_seconds"] = fmt.Sprintf("must be %d..%d",
				minTimeoutSeconds, maxTimeoutSeconds)
		}
	}
	if in.ExpectedStatus.Set {
		set++
		if !in.ExpectedStatus.Null &&
			(in.ExpectedStatus.V < 200 || in.ExpectedStatus.V > 599) {
			f["expected_status"] = "must be 200..599 or null"
		}
	}
	if set == 0 {
		f["_body"] = "at least one field required"
	}
	if len(f) > 0 {
		return fe(f)
	}
	return nil
}

// checkName bounds the label; leading/trailing space is trimmed by the
// service layer before persist (validated on the trimmed form).
func checkName(f map[string]string, key, name string) {
	n := strings.TrimSpace(name)
	if n == "" {
		f[key] = "required"
		return
	}
	if len([]rune(n)) > maxNameRunes {
		f[key] = fmt.Sprintf("must be at most %d characters", maxNameRunes)
	}
}

// checkPolicy enforces interval/timeout bounds and the timeout<interval
// relation — a monitor must finish waiting before the next slot opens.
func checkPolicy(f map[string]string, interval, timeout int, expected *int) {
	if interval < minIntervalSeconds || interval > maxIntervalSeconds {
		f["interval_seconds"] = fmt.Sprintf("must be %d..%d",
			minIntervalSeconds, maxIntervalSeconds)
	}
	if timeout < minTimeoutSeconds || timeout > maxTimeoutSeconds {
		f["timeout_seconds"] = fmt.Sprintf("must be %d..%d",
			minTimeoutSeconds, maxTimeoutSeconds)
	} else if timeout >= interval && interval >= minIntervalSeconds {
		// Only flag the relation when both fields are individually sane.
		f["timeout_seconds"] = "must be less than interval_seconds"
	}
	if expected != nil && (*expected < 200 || *expected > 599) {
		f["expected_status"] = "must be 200..599"
	}
}

// ParseTargetPolicy validates target URL SYNTAX. Rules: http/https
// only, no userinfo, no fragment, host present, port absent/80/443,
// no private/loopback/link-local/unspecified IP literals, bounded
// length, no raw whitespace or credentials. Returns the parsed URL
// only for convenience — the caller must not treat it as SSRF-proven.
func ParseTargetPolicy(raw string) (string, error) {
	if raw == "" {
		return "", fe(map[string]string{"target_url": "required"})
	}
	if len(raw) > maxURLBytes {
		return "", fe(map[string]string{"target_url": "too long"})
	}
	if strings.ContainsAny(raw, " \t\r\n") {
		return "", fe(map[string]string{"target_url": "must not contain whitespace"})
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", fe(map[string]string{"target_url": "invalid URL"})
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fe(map[string]string{"target_url": "scheme must be http or https"})
	}
	if u.User != nil {
		return "", fe(map[string]string{"target_url": "credentials not allowed"})
	}
	if u.Fragment != "" {
		return "", fe(map[string]string{"target_url": "fragment not allowed"})
	}
	if p := u.Port(); p != "" && p != "80" && p != "443" {
		return "", fe(map[string]string{"target_url": "port not allowed"})
	}
	host := u.Hostname()
	if host == "" {
		return "", fe(map[string]string{"target_url": "host required"})
	}
	// Literal IPs get the literal check; DNS names defer all
	// reachability/private-range proof to the dial-time resolver.
	if addr, aerr := netip.ParseAddr(host); aerr == nil {
		if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
			addr.IsLinkLocalMulticast() || addr.IsUnspecified() || addr.IsMulticast() {
			return "", fe(map[string]string{"target_url": "destination not allowed"})
		}
	}
	return raw, nil
}

func checkURL(f map[string]string, key, raw string) {
	if _, err := ParseTargetPolicy(raw); err != nil {
		f[key] = "invalid target"
		var ferr *FieldError
		if errors.As(err, &ferr) {
			if msg, ok := ferr.Fields["target_url"]; ok {
				f[key] = msg
			}
		}
	}
}
