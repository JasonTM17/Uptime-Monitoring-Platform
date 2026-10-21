package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/http"
	"time"
)

// CSRF protection is a signed double-submit cookie, which works BEFORE
// authentication (login CSRF is a real attack: an ambient login binds
// the victim's subsequent activity to the attacker's session).
//
// Token format: base64url(nonce[16] | expiryUnix[8] | tag[16]) where
// tag = HMAC-SHA256(key, nonce|expiry)[:16]. Validation requires:
//   - the uptime_csrf cookie value and X-CSRF-Token header to match
//     exactly (an attacker cannot set the cookie cross-site), and
//   - the signature and TTL to verify against the server key.
//
// Origin is validated separately and exactly — scheme://host[:port]
// string equality against the configured list; no wildcards, no
// suffix matching, no subdomain creep.

var ErrCSRF = errors.New("csrf check failed")

const (
	csrfCookieName   = "uptime_csrf"
	csrfHeader       = "X-CSRF-Token"
	csrfNonceLen     = 16
	csrfTagLen       = 16
	csrfExpiryLen    = 8
	csrfChallengeLen = csrfNonceLen + csrfExpiryLen + csrfTagLen // 40
)

// CSRFManager issues and validates challenges. now is injectable.
type CSRFManager struct {
	key     []byte
	ttl     time.Duration
	secure  bool
	origins map[string]struct{}
	now     func() time.Time
}

func NewCSRFManager(key []byte, ttl time.Duration, secure bool, origins []string) *CSRFManager {
	set := make(map[string]struct{}, len(origins))
	for _, o := range origins {
		set[o] = struct{}{}
	}
	return &CSRFManager{key: key, ttl: ttl, secure: secure,
		origins: set, now: time.Now}
}

// Issue mints a fresh signed challenge and sets the readable cookie.
// The endpoint also returns the token in the JSON body so SPA clients
// need no cookie parsing; the header echo is what proves same-origin.
func (m *CSRFManager) Issue(w http.ResponseWriter) (string, error) {
	nonce := make([]byte, csrfNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	buf := make([]byte, 0, csrfChallengeLen)
	buf = append(buf, nonce...)
	exp := m.now().Add(m.ttl).Unix()
	var eb [8]byte
	binary.BigEndian.PutUint64(eb[:], uint64(exp))
	buf = append(buf, eb[:]...)
	tag := m.tag(buf)
	buf = append(buf, tag...)
	token := base64.RawURLEncoding.EncodeToString(buf)
	http.SetCookie(w, &http.Cookie{
		Name: csrfCookieName, Value: token, Path: "/",
		HttpOnly: false, // SPA reads this cookie to echo the header
		Secure:   m.secure,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Unix(exp, 0),
	})
	return token, nil
}

func (m *CSRFManager) tag(msg []byte) []byte {
	mac := hmac.New(sha256.New, m.key)
	mac.Write(msg)
	return mac.Sum(nil)[:csrfTagLen]
}

// verifyToken checks signature and expiry on an opaque token string.
func (m *CSRFManager) verifyToken(token string) error {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != csrfChallengeLen {
		return ErrCSRF
	}
	payload, tag := raw[:csrfNonceLen+csrfExpiryLen], raw[csrfNonceLen+csrfExpiryLen:]
	if !hmac.Equal(tag, m.tag(payload)) {
		return ErrCSRF
	}
	exp := int64(binary.BigEndian.Uint64(payload[csrfNonceLen:]))
	if m.now().Unix() >= exp {
		return ErrCSRF
	}
	return nil
}

// ValidateOrigin enforces exact-origin match on mutations. A missing
// Origin header on a cookie-bearing mutation is rejected — browsers
// always send Origin on cross-site POSTs, and we require it for all.
func (m *CSRFManager) ValidateOrigin(r *http.Request) error {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return ErrCSRF
	}
	if _, ok := m.origins[origin]; !ok {
		return ErrCSRF
	}
	return nil
}

// Validate checks the full pre-auth contract: exact Origin plus
// cookie/header double-submit with a valid signature and TTL.
func (m *CSRFManager) Validate(r *http.Request) error {
	if err := m.ValidateOrigin(r); err != nil {
		return err
	}
	ck, err := r.Cookie(csrfCookieName)
	if err != nil || ck.Value == "" {
		return ErrCSRF
	}
	hdr := r.Header.Get(csrfHeader)
	if hdr == "" || hdr != ck.Value {
		return ErrCSRF
	}
	return m.verifyToken(hdr)
}

// RequireCSRF wraps a mutation handler. Rejections are a generic 403 —
// no hint which leg failed.
func (m *CSRFManager) RequireCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := m.Validate(r); err != nil {
			writeCSRFError(w, r)
			return
		}
		next(w, r)
	}
}
