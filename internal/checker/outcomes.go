package checker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"syscall"
)

// errPolicyBlocked is the sentinel the destination policy raises.
// Classification maps it to OutcomePolicyBlocked — never DOWN.
var errPolicyBlocked = errors.New("checker: destination blocked by policy")

// errInternal is the sentinel for collector-side faults (allocation,
// protocol violations, pool exhaustion). Never target evidence.
var errInternal = errors.New("checker: internal fault")

// ClassifyError maps a wrapped error to its Outcome using TYPE checks
// only — never err.Error() text, which is neither stable nor safe to
// interpret. Order matters: context reasons win over transport
// errors because a canceled dial still returns a *net.OpError.
func ClassifyError(err error) Outcome {
	if err == nil {
		return OutcomeInternalError
	}
	if errors.Is(err, context.Canceled) {
		return OutcomeCanceled
	}
	if errors.Is(err, errPolicyBlocked) {
		return OutcomePolicyBlocked
	}
	if errors.Is(err, errInternal) {
		return OutcomeInternalError
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return OutcomeTimeout
	}
	var certErr x509.CertificateInvalidError
	var hostErr x509.HostnameError
	var unknownAuthErr x509.UnknownAuthorityError
	var recordErr tls.RecordHeaderError
	var alertErr tls.AlertError
	if errors.As(err, &certErr) || errors.As(err, &hostErr) ||
		errors.As(err, &unknownAuthErr) || errors.As(err, &recordErr) ||
		errors.As(err, &alertErr) {
		return OutcomeTLSError
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return OutcomeDNSError
	}
	// Transport-level failures after DNS: refused, reset, no route,
	// and mid-body truncation — all target-side transport behavior,
	// never collector faults.
	var opErr *net.OpError
	if errors.As(err, &opErr) || errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, io.ErrUnexpectedEOF) {
		return OutcomeConnectError
	}
	// An http client's *url.Error is only a wrapper — classify on the
	// inner error so a non-network failure stays internal, not "connect".
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return ClassifyError(urlErr.Err)
	}
	return OutcomeInternalError
}

// IsExpectedStatus reports whether an observed HTTP status counts as
// healthy for the target: the configured expected_status if set,
// otherwise any 2xx. Note 3xx+ can NEVER be an implicit success —
// redirects are refused at the transport, so a 3xx reaching here is
// already unexpected.
func IsExpectedStatus(t Target, status int) bool {
	if t.ExpectedStatus != nil {
		return status == *t.ExpectedStatus
	}
	return status >= http.StatusOK && status <= 299
}
