package checker

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

// ResolvedTarget is the immutable output of a validated resolution:
// the original host (for SNI/Host header), the implicit port, and
// the COMPLETE set of approved addresses from one lookup. The dialer
// may only ever connect to one of these addresses — this is what
// makes DNS rebinding between validate and dial impossible.
type ResolvedTarget struct {
	scheme string
	host   string
	port   int
	addrs  []netip.Addr
}

func (r ResolvedTarget) Scheme() string { return r.scheme }
func (r ResolvedTarget) Host() string   { return r.host }
func (r ResolvedTarget) Port() int      { return r.port }

// Addrs returns a defensive copy — the approved set can never be
// mutated by a caller or a misbehaving resolver.
func (r ResolvedTarget) Addrs() []netip.Addr {
	out := make([]netip.Addr, len(r.addrs))
	copy(out, r.addrs)
	return out
}

// ResolveValidated performs one bounded lookup and returns a target
// that is dialable ONLY when every single answer validates as public.
// A hostname that resolves to even one denied address fails the whole
// resolution (mixed-answer rebinding). A literal target skips the
// lookup entirely — literals were already validated by ParseTarget.
func ResolveValidated(ctx context.Context, res Resolver, pt ParsedTarget) (ResolvedTarget, error) {
	if pt.Literal.IsValid() {
		return ResolvedTarget{
			scheme: pt.Scheme, host: pt.Host, port: pt.Port,
			addrs: []netip.Addr{pt.Literal.Unmap()},
		}, nil
	}
	ips, err := res.LookupIP(ctx, pt.Host)
	if err != nil {
		return ResolvedTarget{}, fmt.Errorf("resolve %q: %w", pt.Host, err)
	}
	if len(ips) == 0 {
		return ResolvedTarget{}, &net.DNSError{
			Err: "no such host", Name: pt.Host, IsNotFound: true,
		}
	}
	seen := make(map[netip.Addr]bool, len(ips))
	addrs := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			return ResolvedTarget{}, fmt.Errorf("%w: unparseable resolver answer", errPolicyBlocked)
		}
		addr = addr.Unmap()
		if err := ValidatePublicAddress(addr); err != nil {
			return ResolvedTarget{}, err
		}
		if !seen[addr] {
			seen[addr] = true
			addrs = append(addrs, addr)
		}
	}
	return ResolvedTarget{
		scheme: pt.Scheme, host: pt.Host, port: pt.Port, addrs: addrs,
	}, nil
}
