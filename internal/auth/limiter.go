package auth

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// attemptLimiter is a fixed-window, memory-bounded rate limiter. It is
// deliberately simple: a single instance guards one process (hosted
// distributed limiting is a future concern per the security spec).
//
// Invariants:
//   - keys map is capped — at cap, NEW keys are refused admission
//     (fail closed as "limited") while existing keys keep their budget;
//   - expired windows are reaped on access and periodically;
//   - nothing here ever blocks on KDF work (the hash gate is separate).
type attemptLimiter struct {
	mu     sync.Mutex
	max    int           // attempts allowed per window
	window time.Duration // fixed-window length
	cap    int           // hard bound on tracked keys
	now    func() time.Time
	b      map[string]*attemptBucket
}

type attemptBucket struct {
	count   int
	resetAt time.Time
}

func newAttemptLimiter(maxPerWindow int, window time.Duration, maxKeys int) *attemptLimiter {
	return &attemptLimiter{
		max: maxPerWindow, window: window, cap: maxKeys,
		now: time.Now, b: make(map[string]*attemptBucket),
	}
}

// allow records one attempt for key and reports whether it was admitted
// plus the wait until the next slot (0 when admitted).
func (l *attemptLimiter) allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	bk, ok := l.b[key]
	if ok && !now.Before(bk.resetAt) {
		delete(l.b, key) // window expired
		ok = false
	}
	if !ok {
		if len(l.b) >= l.cap {
			l.evictExpiredLocked(now)
			if len(l.b) >= l.cap {
				// Map saturated with live keys: refuse admission of new
				// keys rather than grow unbounded.
				return false, l.window
			}
		}
		bk = &attemptBucket{resetAt: now.Add(l.window)}
		l.b[key] = bk
	}
	bk.count++
	if bk.count > l.max {
		return false, time.Until(bk.resetAt)
	}
	return true, 0
}

func (l *attemptLimiter) evictExpiredLocked(now time.Time) {
	for k, bk := range l.b {
		if !now.Before(bk.resetAt) {
			delete(l.b, k)
		}
	}
}

// keys reports the tracked-key count (tests/metrics only).
func (l *attemptLimiter) keys() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.b)
}

// ClientIP resolves the caller address. Forwarded headers are honored
// only when the direct peer sits inside a configured trusted-proxy
// CIDR — a spoofed X-Forwarded-For from an untrusted peer is ignored.
func ClientIP(r *http.Request, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remote, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	if !inTrusted(remote, trusted) {
		return remote.String()
	}
	// Trusted peer: walk XFF right-to-left; the first address not
	// itself trusted is the real client.
	for _, h := range []string{r.Header.Get("X-Forwarded-For")} {
		parts := strings.Split(h, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			cand, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
			if err != nil {
				continue
			}
			if !inTrusted(cand, trusted) {
				return cand.String()
			}
		}
	}
	return remote.String()
}

func inTrusted(addr netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
