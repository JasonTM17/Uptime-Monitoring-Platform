package checker

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
)

func testTarget() Target {
	return Target{
		MonitorID:      uuid.MustParse("00000000-0000-0000-0000-000000000099"),
		URL:            "https://example.com/health",
		TimeoutSeconds: 5,
	}
}

func i64(v int64) *int64 { return &v }
func istatus(v int) *int { return &v }

func TestObservationContract(t *testing.T) {
	tg := testTarget()
	cases := []struct {
		name      string
		outcome   Outcome
		status    *int
		latency   *int64
		wantErr   bool
		wantClass bool // ErrorClass non-nil after build
	}{
		{"success-200", OutcomeSuccess, istatus(200), i64(42), false, false},
		{"success-custom-404", OutcomeSuccess, istatus(404), i64(9), false, false},
		{"success-nil-status", OutcomeSuccess, nil, i64(9), true, false},
		{"success-status-0", OutcomeSuccess, istatus(0), i64(9), true, false},
		{"success-status-99", OutcomeSuccess, istatus(99), i64(9), true, false},
		{"success-status-600", OutcomeSuccess, istatus(600), i64(9), true, false},
		{"unexpected-500", OutcomeUnexpectedStatus, istatus(500), i64(120), false, false},
		{"unexpected-nil-status", OutcomeUnexpectedStatus, nil, i64(120), true, false},
		{"dns-failure", OutcomeDNSError, nil, i64(30), false, true},
		{"dns-with-status", OutcomeDNSError, istatus(503), i64(30), true, false},
		{"connect-failure", OutcomeConnectError, nil, i64(15), false, true},
		{"timeout", OutcomeTimeout, nil, i64(5000), false, true},
		{"policy-blocked", OutcomePolicyBlocked, nil, nil, false, true},
		{"policy-blocked-with-status", OutcomePolicyBlocked, istatus(200), nil, true, false},
		{"canceled", OutcomeCanceled, nil, nil, false, true},
		{"internal", OutcomeInternalError, nil, nil, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, err := NewObservation(tg, tc.outcome, tc.status, tc.latency, time.Now())
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected invariant rejection")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected rejection: %v", err)
			}
			if (o.ErrorClass != nil) != tc.wantClass {
				t.Errorf("ErrorClass presence = %v, want %v", o.ErrorClass != nil, tc.wantClass)
			}
			if o.CheckedAt.Location() != time.UTC {
				t.Error("CheckedAt not UTC")
			}
		})
	}
}

func TestOutcomeEligibility(t *testing.T) {
	for oc := OutcomeSuccess; oc <= OutcomeTimeout; oc++ {
		if !oc.IsEligible() {
			t.Errorf("outcome %d should be target evidence", oc)
		}
	}
	for oc := OutcomePolicyBlocked; oc <= OutcomeInternalError; oc++ {
		if oc.IsEligible() {
			t.Errorf("outcome %d must not be target evidence", oc)
		}
	}
}

func TestClassifyError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want Outcome
	}{
		{"nil", nil, OutcomeInternalError},
		{"explicit-canceled", context.Canceled, OutcomeCanceled},
		{"wrapped-canceled", fmt.Errorf("dial: %w", context.Canceled), OutcomeCanceled},
		{"deadline", context.DeadlineExceeded, OutcomeTimeout},
		{"wrapped-deadline", fmt.Errorf("http: %w", context.DeadlineExceeded), OutcomeTimeout},
		{"policy", errPolicyBlocked, OutcomePolicyBlocked},
		{"wrapped-policy", fmt.Errorf("resolve: %w", errPolicyBlocked), OutcomePolicyBlocked},
		{"internal", errInternal, OutcomeInternalError},
		{"dns-nxdomain", &net.DNSError{IsNotFound: true, Name: "x.test", Server: "ns"}, OutcomeDNSError},
		{"wrapped-dns", &url.Error{Op: "Get", URL: "u", Err: &net.DNSError{Err: "no such host"}}, OutcomeDNSError},
		{"connrefused", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, OutcomeConnectError},
		{"url-refused", &url.Error{Op: "Get", URL: "u", Err: &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}}, OutcomeConnectError},
		{"hostname-mismatch", x509.HostnameError{Host: "a", Certificate: &x509.Certificate{}}, OutcomeTLSError},
		{"unknown-authority", x509.UnknownAuthorityError{Cert: &x509.Certificate{}}, OutcomeTLSError},
		{"cert-invalid", x509.CertificateInvalidError{Cert: &x509.Certificate{}}, OutcomeTLSError},
		{"wrapped-tls", &url.Error{Op: "Get", URL: "u", Err: x509.HostnameError{}}, OutcomeTLSError},
		{"unknown", errors.New("mystery"), OutcomeInternalError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyError(tc.err); got != tc.want {
				t.Errorf("ClassifyError = %d, want %d", got, tc.want)
			}
		})
	}
}

// An observation never carries raw error text — a canary token or URL
// query embedded in the underlying error must be absent from every
// serialized form of the public result.
func TestOutcomeRedaction(t *testing.T) {
	tg := testTarget()
	canary := "sk_live_canary_7f3b2c1d"
	inner := &net.DNSError{
		Err:  "lookup failed",
		Name: "host?" + canary,
	}
	wrapped := &url.Error{Op: "Get", URL: "https://x.test/?k=" + canary, Err: inner}
	oc := ClassifyError(wrapped)
	o, err := NewObservation(tg, oc, nil, i64(12), time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	raw, merr := json.Marshal(o)
	if merr != nil {
		t.Fatalf("marshal: %v", merr)
	}
	for _, surface := range []string{string(raw), fmt.Sprintf("%+v", o)} {
		if strings.Contains(surface, canary) {
			t.Fatalf("canary leaked into observation surface: %s", surface)
		}
	}
}

func TestIsExpectedStatus(t *testing.T) {
	tg := testTarget()
	exp := 418
	cases := []struct {
		name   string
		target Target
		status int
		want   bool
	}{
		{"default-200", tg, 200, true},
		{"default-299", tg, 299, true},
		{"default-300-not-2xx", tg, 300, false},
		{"default-500", tg, 500, false},
		{"default-199", tg, 199, false},
		{"custom-match", Target{ExpectedStatus: &exp}, 418, true},
		{"custom-miss-2xx", Target{ExpectedStatus: &exp}, 200, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsExpectedStatus(tc.target, tc.status); got != tc.want {
				t.Errorf("IsExpectedStatus = %v, want %v", got, tc.want)
			}
		})
	}
}
