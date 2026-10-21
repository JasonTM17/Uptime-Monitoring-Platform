package checker

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// DialFunc dials a concrete ip:port. Production uses net.Dialer;
// tests inject a recorder. The dialer NEVER resolves names — the
// address it receives is already a member of the approved set.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

func defaultDial(ctx context.Context, network, address string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	return d.DialContext(ctx, network, address)
}

// newSafeTransport builds a transport whose every connection is
// pinned to the approved address set of ONE resolved target:
//   - DialContext dials approved IP:port, never the request hostname —
//     DNS cannot be re-asked between validation and dial (rebinding).
//   - TLS ServerName stays the ORIGINAL hostname — certificate
//     verification is unaffected by the pinned dial address.
//   - Proxy is nil — HTTP_PROXY/HTTPS_PROXY environment variables
//     cannot reroute the connection.
//   - Keep-alives and HTTP/2 disabled — no cross-request reuse, no
//     coalescing a later connection onto this target's socket.
func newSafeTransport(rt ResolvedTarget, dial DialFunc) *http.Transport {
	addrs := rt.Addrs()
	return &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		ForceAttemptHTTP2: false,
		TLSClientConfig: &tls.Config{
			ServerName:         rt.Host(),
			InsecureSkipVerify: false, // never — verification is the point
			MinVersion:         tls.VersionTLS12,
		},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var lastErr error
			for _, a := range addrs {
				conn, err := dial(ctx, "tcp",
					net.JoinHostPort(a.String(), fmt.Sprint(rt.Port())))
				if err == nil {
					return conn, nil
				}
				lastErr = err
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
			}
			return nil, lastErr
		},
	}
}

// NewSafeTransport is the production constructor — same guarantees,
// real socket dialer. The transport is single-target and must not be
// shared across resolved targets.
func NewSafeTransport(rt ResolvedTarget) *http.Transport {
	return newSafeTransport(rt, defaultDial)
}

// newClient composes transport + redirect refusal. Redirects are not
// followed at all: a 3xx is the target's answer (usually
// OutcomeUnexpectedStatus), never an invitation to a second,
// unvalidated dial.
func newClient(rt ResolvedTarget, dial DialFunc) *http.Client {
	return &http.Client{
		Transport: newSafeTransport(rt, dial),
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// BuildRequest creates the check request against the RESOLVED host
// view: canonical host (no trailing dot), scheme, and the original
// path/query from the stored URL. The request's URL hostname is the
// hostname — the transport swaps the dial target underneath it.
func BuildRequest(ctx context.Context, rt ResolvedTarget, rawURL string) (*http.Request, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%w: rebuild url: %v", errInternal, err)
	}
	u.Scheme = rt.Scheme()
	u.Host = rt.Host()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %v", errInternal, err)
	}
	req.Header.Set("User-Agent", "uptime-checker/0.1 (+local)")
	req.Header.Set("Accept", "*/*")
	// Minimal surface — no cookies, no auth headers ever cross this
	// boundary to an operator-chosen destination.
	return req, nil
}
