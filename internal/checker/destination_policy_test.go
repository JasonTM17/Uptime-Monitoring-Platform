package checker

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
)

// C28's red→green contract: the independent C27 oracle drives the
// implementation assertions. Every address case must validate to the
// captured decision; every URL case must parse to the captured
// decision.
func TestDestinationPolicyFixtures(t *testing.T) {
	f := loadDestinationFixture(t)
	for _, c := range f.AddressCases {
		t.Run(c.ID, func(t *testing.T) {
			addr, err := netip.ParseAddr(c.Input)
			if err != nil {
				t.Fatalf("fixture input broken: %v", err)
			}
			got := ValidatePublicAddress(addr)
			switch c.Decision {
			case "allow":
				if got != nil {
					t.Errorf("%s should be allowed, got %v", c.Input, got)
				}
			case "deny":
				if got == nil {
					t.Errorf("%s should be denied (%s)", c.Input, c.Reason)
				} else if !errors.Is(got, errPolicyBlocked) {
					t.Errorf("denial for %s must wrap errPolicyBlocked, got %v", c.Input, got)
				}
			}
		})
	}
}

func TestTargetURLFixtures(t *testing.T) {
	f := loadDestinationFixture(t)
	for _, c := range f.URLCases {
		t.Run(c.ID, func(t *testing.T) {
			pt, err := ParseTarget(c.Input)
			switch c.Decision {
			case "allow":
				if err != nil {
					t.Errorf("%s should parse, got %v", c.Input, err)
				} else if pt.Host == "" {
					t.Errorf("%s parsed with empty host", c.Input)
				}
			case "deny":
				if err == nil {
					t.Errorf("%s should be denied (%s)", c.Input, c.Reason)
				} else if !errors.Is(err, errPolicyBlocked) {
					t.Errorf("denial for %s must wrap errPolicyBlocked, got %v", c.Input, err)
				}
			}
		})
	}
}

func TestParseTargetCanonicalization(t *testing.T) {
	pt, err := ParseTarget("https://public.example./health")
	if err != nil {
		t.Fatalf("trailing dot should be accepted: %v", err)
	}
	if pt.Host != "public.example" {
		t.Errorf("trailing dot not stripped: %q", pt.Host)
	}
	if pt.Port != 443 {
		t.Errorf("https port = %d, want 443", pt.Port)
	}
	pt2, err := ParseTarget("http://public.example/x")
	if err != nil {
		t.Fatal(err)
	}
	if pt2.Port != 80 {
		t.Errorf("http port = %d, want 80", pt2.Port)
	}
}

func TestEncodedLiteralDenied(t *testing.T) {
	for _, host := range []string{
		"http://0x7f000001/", "http://2130706433/", "http://0177.0.0.1/",
		"http://127.1/", "http://0x08080808.0x08080808.0x08080808.0x08080808/",
	} {
		_, err := ParseTarget(host)
		if host == "http://0x08080808.0x08080808.0x08080808.0x08080808/" {
			// encodes 8.8.8.8 — public, allowed as literal
			if err != nil {
				t.Errorf("%s decodes to public 8.8.8.8, should parse: %v", host, err)
			}
			continue
		}
		if !errors.Is(err, errPolicyBlocked) {
			t.Errorf("%s should be policy-denied (encoded internal IP), got %v", host, err)
		}
	}
}

// fakeResolver returns scripted answers and records calls.
type fakeResolver struct {
	answers []net.IP
	err     error
	mu      sync.Mutex
	calls   int
}

func (f *fakeResolver) LookupIP(_ context.Context, _ string) ([]net.IP, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.answers, f.err
}

func ipa(s string) net.IP { return net.ParseIP(s) }

func TestResolveValidated(t *testing.T) {
	ctx := context.Background()
	pt := func(url string) ParsedTarget {
		p, err := ParseTarget(url)
		if err != nil {
			t.Fatalf("ParseTarget(%q): %v", url, err)
		}
		return p
	}

	t.Run("all-public", func(t *testing.T) {
		res := &fakeResolver{answers: []net.IP{ipa("8.8.8.8"), ipa("1.1.1.1")}}
		rt, err := ResolveValidated(ctx, res, pt("https://ok.example/"))
		if err != nil {
			t.Fatalf("public answers should resolve: %v", err)
		}
		if len(rt.Addrs()) != 2 || res.calls != 1 {
			t.Errorf("got %v addrs / %d calls", rt.Addrs(), res.calls)
		}
	})

	t.Run("mixed-answers-deny-whole-resolution", func(t *testing.T) {
		res := &fakeResolver{answers: []net.IP{ipa("8.8.8.8"), ipa("10.0.0.4")}}
		_, err := ResolveValidated(ctx, res, pt("https://ok.example/"))
		if !errors.Is(err, errPolicyBlocked) {
			t.Errorf("mixed answer must fail whole resolution as policy, got %v", err)
		}
	})

	t.Run("all-private", func(t *testing.T) {
		res := &fakeResolver{answers: []net.IP{ipa("192.168.1.1"), ipa("172.16.0.9")}}
		_, err := ResolveValidated(ctx, res, pt("https://ok.example/"))
		if !errors.Is(err, errPolicyBlocked) {
			t.Errorf("got %v", err)
		}
	})

	t.Run("empty-answers-is-dns-error", func(t *testing.T) {
		res := &fakeResolver{answers: nil}
		_, err := ResolveValidated(ctx, res, pt("https://ok.example/"))
		if ClassifyError(err) != OutcomeDNSError {
			t.Errorf("empty answers must classify DNS_ERROR, got %v (%v)", ClassifyError(err), err)
		}
	})

	t.Run("nxdomain-propagates-dns", func(t *testing.T) {
		res := &fakeResolver{err: &net.DNSError{Err: "no such host", IsNotFound: true}}
		_, err := ResolveValidated(ctx, res, pt("https://ok.example/"))
		if ClassifyError(err) != OutcomeDNSError {
			t.Errorf("got %v", ClassifyError(err))
		}
	})

	t.Run("resolver-deadline-propagates", func(t *testing.T) {
		res := &fakeResolver{err: context.DeadlineExceeded}
		_, err := ResolveValidated(ctx, res, pt("https://ok.example/"))
		if ClassifyError(err) != OutcomeTimeout {
			t.Errorf("got %v", ClassifyError(err))
		}
	})

	t.Run("literal-skips-lookup", func(t *testing.T) {
		res := &fakeResolver{}
		parsed, err := ParseTarget("https://8.8.8.8/")
		if err != nil {
			t.Fatal(err)
		}
		rt, err := ResolveValidated(ctx, res, parsed)
		if err != nil {
			t.Fatal(err)
		}
		if res.calls != 0 {
			t.Error("literal target must not hit the resolver")
		}
		if rt.Addrs()[0] != netip.MustParseAddr("8.8.8.8") {
			t.Errorf("literal addr = %v", rt.Addrs())
		}
	})

	t.Run("denied-literal-never-dials", func(t *testing.T) {
		if _, err := ParseTarget("http://127.0.0.1/"); !errors.Is(err, errPolicyBlocked) {
			t.Fatalf("literal loopback should be denied, got %v", err)
		}
	})

	t.Run("mutated-resolver-buffer", func(t *testing.T) {
		// A resolver that returns a slice then mutates it must not
		// corrupt the approved set — we copy via AddrFromSlice.
		res := &fakeResolver{answers: []net.IP{ipa("8.8.8.8")}}
		rt, err := ResolveValidated(ctx, res, pt("https://ok.example/"))
		if err != nil {
			t.Fatal(err)
		}
		res.answers[0] = net.ParseIP("127.0.0.1")
		if rt.Addrs()[0] != netip.MustParseAddr("8.8.8.8") {
			t.Error("approved set mutated by resolver buffer change")
		}
	})

	t.Run("mapped-private-answer-denied", func(t *testing.T) {
		res := &fakeResolver{answers: []net.IP{ipa("::ffff:10.0.0.9")}}
		_, err := ResolveValidated(ctx, res, pt("https://ok.example/"))
		if !errors.Is(err, errPolicyBlocked) {
			t.Errorf("mapped private answer must deny, got %v", err)
		}
	})

	t.Run("addrs-returns-copy", func(t *testing.T) {
		res := &fakeResolver{answers: []net.IP{ipa("8.8.8.8")}}
		rt, err := ResolveValidated(ctx, res, pt("https://ok.example/"))
		if err != nil {
			t.Fatal(err)
		}
		out := rt.Addrs()
		out[0] = netip.MustParseAddr("127.0.0.1")
		if rt.Addrs()[0] != netip.MustParseAddr("8.8.8.8") {
			t.Error("Addrs did not return a defensive copy")
		}
	})
}
