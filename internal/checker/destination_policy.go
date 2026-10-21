package checker

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// Deny prefixes beyond the built-in netip signals — IANA
// special-purpose ranges that IsGlobalUnicast happily reports as
// global. Captured from the IANA registries (see
// testdata/destination-policy.json for source dates).
var deniedV4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network" RFC 791
	netip.MustParsePrefix("10.0.0.0/8"),      // RFC 1918
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT RFC 6598
	netip.MustParsePrefix("127.0.0.0/8"),     // loopback
	netip.MustParsePrefix("169.254.0.0/16"),  // link-local
	netip.MustParsePrefix("172.16.0.0/12"),   // RFC 1918
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("192.168.0.0/16"),  // RFC 1918
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking RFC 2544
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("192.31.196.0/24"), // AS112 anycast
	netip.MustParsePrefix("192.52.193.0/24"), // AMT anycast
	netip.MustParsePrefix("192.88.99.0/24"),  // 6to4 relay anycast
	netip.MustParsePrefix("192.175.48.0/24"), // AS112 direct delegation
	netip.MustParsePrefix("224.0.0.0/4"),     // multicast
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved / broadcast
}

var deniedV6 = []netip.Prefix{
	netip.MustParsePrefix("::/128"),            // unspecified
	netip.MustParsePrefix("::1/128"),           // loopback
	netip.MustParsePrefix("::/96"),             // IPv4-compatible (deprecated)
	netip.MustParsePrefix("::ffff:0:0/96"),     // mapped — belt, unmap handles
	netip.MustParsePrefix("64:ff9b::/96"),      // NAT64 WKP — embeds arbitrary IPv4
	netip.MustParsePrefix("64:ff9b:1::/48"),    // local-use translation
	netip.MustParsePrefix("100::/64"),          // discard-only RFC 6666
	netip.MustParsePrefix("2001::/23"),         // IETF protocol assignments (teredo/sub ranges)
	netip.MustParsePrefix("2001:db8::/32"),     // documentation
	netip.MustParsePrefix("2002::/16"),         // 6to4 — embeds IPv4, deprecated
	netip.MustParsePrefix("3fff::/20"),         // RFC 9637 documentation
	netip.MustParsePrefix("5f00::/16"),         // SRv6 SID — not a destination
	netip.MustParsePrefix("2620:4f:8000::/48"), // AS112 anycast
	netip.MustParsePrefix("fc00::/7"),          // unique-local
	netip.MustParsePrefix("fe80::/10"),         // link-local
	netip.MustParsePrefix("fec0::/10"),         // site-local (deprecated)
	netip.MustParsePrefix("ff00::/8"),          // multicast
}

// ValidatePublicAddress is the single authority on dialable
// destinations: public global unicast only. Unmaps IPv4-mapped IPv6
// BEFORE classifying, denies scoped addresses outright, and requires
// every denied-prefix check to pass. Errors wrap errPolicyBlocked —
// a destination OUR policy refused, never a target failure.
func ValidatePublicAddress(addr netip.Addr) error {
	if addr.Zone() != "" {
		return fmt.Errorf("%w: zone-scoped address", errPolicyBlocked)
	}
	a := addr.Unmap()
	if !a.IsGlobalUnicast() {
		return fmt.Errorf("%w: non-global-unicast address", errPolicyBlocked)
	}
	deny := deniedV6
	if a.Is4() {
		deny = deniedV4
	}
	for _, p := range deny {
		if p.Contains(a) {
			return fmt.Errorf("%w: address in special-purpose range %s", errPolicyBlocked, p)
		}
	}
	return nil
}

// ParsedTarget is the canonical URL view used for resolution and the
// eventual request: scheme, A-label hostname (no trailing dot, no
// userinfo), port (explicit when stated, otherwise scheme default),
// and a pre-validated literal when the host was an IP in any form —
// literals skip DNS entirely.
type ParsedTarget struct {
	Scheme  string
	Host    string // A-label form — used for lookup, SNI, and Host
	Port    int
	Literal netip.Addr // valid iff host was an address literal
}

// ParseTarget canonicalizes a stored monitor URL and MUST match the
// C19 create-time contract exactly: http/https only, no userinfo, and
// an explicit port only in {80, 443} — the port is then honored
// literally (http://x:443 means plain HTTP over 443). A mismatch here
// would silently policy-block a monitor the API accepted. Denials
// wrap errPolicyBlocked so they classify as POLICY_BLOCKED, never DNS.
func ParseTarget(raw string) (ParsedTarget, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return ParsedTarget{}, fmt.Errorf("%w: unparseable url", errPolicyBlocked)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ParsedTarget{}, fmt.Errorf("%w: scheme %q not checkable", errPolicyBlocked, u.Scheme)
	}
	if u.User != nil {
		return ParsedTarget{}, fmt.Errorf("%w: userinfo not permitted", errPolicyBlocked)
	}
	host := u.Hostname()
	if host == "" {
		return ParsedTarget{}, fmt.Errorf("%w: empty host", errPolicyBlocked)
	}
	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if p := u.Port(); p != "" {
		// C19 contract: explicit port only 80 or 443, on either scheme.
		n, perr := strconv.Atoi(p)
		if perr != nil || (n != 80 && n != 443) {
			return ParsedTarget{}, fmt.Errorf("%w: port %q not permitted", errPolicyBlocked, p)
		}
		port = n
	}
	host = strings.TrimSuffix(host, ".")
	pt := ParsedTarget{Scheme: u.Scheme, Host: host, Port: port}
	if addr, aerr := netip.ParseAddr(host); aerr == nil {
		pt.Literal = addr
		return pt, validateLiteral(addr)
	}
	// inet_aton legacy forms (decimal/hex/octal, 1–4 parts) — decode
	// and classify as a literal so encoded internal IPs never reach
	// DNS as an innocent-looking hostname.
	if addr, ok := decodeLegacyIPv4(host); ok {
		pt.Literal = addr
		return pt, validateLiteral(addr)
	}
	// IDNA → A-label: the U-label form fails DNS resolution outright
	// and can never match certificate SANs — normalize once here so
	// lookup, SNI, and the Host header all see the same wire name.
	ascii, aerr := idna.Lookup.ToASCII(host)
	if aerr != nil || ascii == "" {
		return ParsedTarget{}, fmt.Errorf("%w: host %q is not a valid DNS name", errPolicyBlocked, host)
	}
	pt.Host = ascii
	return pt, nil
}

func validateLiteral(addr netip.Addr) error {
	if err := ValidatePublicAddress(addr); err != nil {
		return err
	}
	return nil
}

// decodeLegacyIPv4 recognizes inet_aton-style hostnames: "2130706433",
// "0x7f000001", "0177.0.0.1", "127.1". Each part parses with base
// detection; the final part may span the remaining bytes.
func decodeLegacyIPv4(host string) (netip.Addr, bool) {
	parts := strings.Split(host, ".")
	if len(parts) > 4 {
		return netip.Addr{}, false
	}
	var nums [4]uint64
	for i, p := range parts {
		if p == "" {
			return netip.Addr{}, false
		}
		n, err := strconv.ParseUint(p, 0, 64)
		if err != nil {
			return netip.Addr{}, false // any non-numeric part → hostname
		}
		nums[i] = n
	}
	var v uint64
	switch len(parts) {
	case 1:
		if nums[0] > 0xFFFFFFFF {
			return netip.Addr{}, false
		}
		v = nums[0]
	case 2:
		if nums[0] > 0xFF || nums[1] > 0xFFFFFF {
			return netip.Addr{}, false
		}
		v = nums[0]<<24 | nums[1]
	case 3:
		if nums[0] > 0xFF || nums[1] > 0xFF || nums[2] > 0xFFFF {
			return netip.Addr{}, false
		}
		v = nums[0]<<24 | nums[1]<<16 | nums[2]
	case 4:
		for i := 0; i < 4; i++ {
			if nums[i] > 0xFF {
				return netip.Addr{}, false
			}
		}
		v = nums[0]<<24 | nums[1]<<16 | nums[2]<<8 | nums[3]
	}
	b := [4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
	return netip.AddrFrom4(b), true
}

// Resolver abstracts DNS for injection; production uses net.Resolver.
type Resolver interface {
	LookupIP(ctx context.Context, host string) ([]net.IP, error)
}

// SystemResolver is the production resolver over the OS config.
type SystemResolver struct{}

func (SystemResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}
