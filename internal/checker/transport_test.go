package checker

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// testResolved constructs a ResolvedTarget directly — bypassing DNS —
// the way a test composes the same production object the resolver
// would emit. The checker package is the only place this seam exists.
func testResolved(host string, port int, addrs ...string) ResolvedTarget {
	return testResolvedScheme("https", host, port, addrs...)
}

func testResolvedScheme(scheme, host string, port int, addrs ...string) ResolvedTarget {
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, netip.MustParseAddr(a))
	}
	return ResolvedTarget{scheme: scheme, host: host, port: port, addrs: out}
}

// recorderDial never opens a socket — it captures the dialed address
// and returns a pipe connected to a scripted response writer.
func recorderDial(t *testing.T, seen *[]string, respond func(net.Conn)) DialFunc {
	return func(_ context.Context, _, address string) (net.Conn, error) {
		*seen = append(*seen, address)
		client, server := net.Pipe()
		go respond(server)
		return client, nil
	}
}

func serveHTTP(conn net.Conn, status int, body string) {
	defer conn.Close()
	buf := make([]byte, 4096)
	conn.Read(buf) // consume request line+headers (bounded test read)
	conn.Write([]byte("HTTP/1.1 " + itoa(status) + " " + http.StatusText(status) + "\r\n" +
		"Content-Length: " + itoa(len(body)) + "\r\n\r\n" + body))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func TestPinnedDial(t *testing.T) {
	var seen []string
	rt := testResolved("pinned.example", 443, "93.184.216.34", "93.184.216.35")
	tr := newSafeTransport(rt, recorderDial(t, &seen, func(c net.Conn) {
		serveHTTP(c, 200, "ok")
	}))
	req, err := BuildRequest(context.Background(), rt, "https://pinned.example/health")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		// HTTP over a pipe on port 443 with TLS config → handshake fails
		// on plain bytes. For the dial-pin assertion we only need the
		// RECORDED address, which is already captured.
		if len(seen) == 0 {
			t.Fatalf("no dial recorded, err %v", err)
		}
	} else {
		resp.Body.Close()
	}
	if len(seen) == 0 {
		t.Fatal("no dial attempted")
	}
	want := "93.184.216.34:443"
	if seen[0] != want {
		t.Fatalf("dialed %q, want approved %q — hostname must never be dialed", seen[0], want)
	}
	for _, a := range seen {
		if a != "93.184.216.34:443" && a != "93.184.216.35:443" {
			t.Fatalf("dialed unapproved address %q", a)
		}
	}
}

func TestDialFailoverStaysInSet(t *testing.T) {
	var seen []string
	var mu sync.Mutex
	rt := testResolved("fail.example", 80, "1.2.3.4", "5.6.7.8")
	failFirst := func(_ context.Context, _, address string) (net.Conn, error) {
		mu.Lock()
		*(&seen) = append(seen, address)
		mu.Unlock()
		return nil, context.DeadlineExceeded // first dial fails; fallback allowed
	}
	tr := newSafeTransport(rt, failFirst)
	req, _ := BuildRequest(context.Background(), rt, "http://fail.example/")
	_, err := tr.RoundTrip(req)
	if err == nil {
		t.Fatal("expected dial failure")
	}
	for _, a := range seen {
		if a != "1.2.3.4:80" && a != "5.6.7.8:80" {
			t.Fatalf("failover dialed unapproved %q", a)
		}
	}
}

// A real CA + server on a pipe proves the ORIGINAL hostname is
// verified even though the dial is pinned to an IP.
func testCA(t *testing.T, cn string) (*x509.CertPool, tls.Certificate) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{cn},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// tlsStub starts a real TLS server on loopback (kernel-buffered — a
// synchronous net.Pipe deadlocks TLS 1.3's overlapping flights) and
// returns a dial func that RECORDS the requested pinned address but
// physically connects to the listener.
func tlsStub(t *testing.T, srvTLS *tls.Config, seen *[]string, respond func(net.Conn)) (DialFunc, net.Addr) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go respond(conn)
		}
	}()
	return func(_ context.Context, _, address string) (net.Conn, error) {
		*seen = append(*seen, address)
		d := &net.Dialer{Timeout: 2 * time.Second}
		return d.DialContext(context.Background(), "tcp", ln.Addr().String())
	}, ln.Addr()
}

func TestOriginalTLSName(t *testing.T) {
	rt := testResolved("pin-check.example", 443, "203.0.113.7")
	pool, srvCert := testCA(t, "pin-check.example")
	var seen []string
	dial, _ := tlsStub(t, &tls.Config{Certificates: []tls.Certificate{srvCert}}, &seen,
		func(conn net.Conn) {
			defer conn.Close()
			srv := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{srvCert}})
			if err := srv.Handshake(); err != nil {
				return
			}
			buf := make([]byte, 4096)
			srv.Read(buf)
			srv.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
		})
	tr := newSafeTransport(rt, dial)
	tr.TLSClientConfig.RootCAs = pool
	req, _ := BuildRequest(context.Background(), rt, "https://pin-check.example/")
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("valid CA + original hostname should pass: %v", err)
	}
	resp.Body.Close()
	if len(seen) == 0 || seen[0] != "203.0.113.7:443" {
		t.Fatalf("dial not pinned to approved address: %v", seen)
	}

	// Same composition, cert for the WRONG name → must fail.
	rt2 := testResolved("other.example", 443, "203.0.113.7")
	pool2, srvCert2 := testCA(t, "not-the-host.example")
	var seen2 []string
	dial2, _ := tlsStub(t, &tls.Config{Certificates: []tls.Certificate{srvCert2}}, &seen2,
		func(conn net.Conn) {
			defer conn.Close()
			srv := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{srvCert2}})
			srv.Handshake()
		})
	tr2 := newSafeTransport(rt2, dial2)
	tr2.TLSClientConfig.RootCAs = pool2
	req2, _ := BuildRequest(context.Background(), rt2, "https://other.example/")
	if _, err := tr2.RoundTrip(req2); err == nil {
		t.Fatal("hostname mismatch must fail TLS verification")
	}
}

func TestProxyEnvironmentIgnored(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	var seen []string
	rt := testResolvedScheme("http", "no-proxy.example", 80, "93.184.216.34")
	tr := newSafeTransport(rt, recorderDial(t, &seen, func(c net.Conn) {
		serveHTTP(c, 200, "ok")
	}))
	req, _ := BuildRequest(context.Background(), rt, "http://no-proxy.example/")
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(seen) != 1 || seen[0] != "93.184.216.34:80" {
		t.Fatalf("proxy env leaked into dial: %v", seen)
	}
}

func TestConcurrentTargetIsolation(t *testing.T) {
	// Two transports built for different targets must not leak
	// approved sets — each transport binds its own ResolvedTarget.
	rtA := testResolved("a.example", 443, "93.184.216.1")
	rtB := testResolved("b.example", 443, "93.184.216.2")
	var seenA, seenB []string
	var mu sync.Mutex
	dialA := func(_ context.Context, _, a string) (net.Conn, error) {
		mu.Lock()
		seenA = append(seenA, a)
		mu.Unlock()
		return nil, context.DeadlineExceeded
	}
	dialB := func(_ context.Context, _, a string) (net.Conn, error) {
		mu.Lock()
		seenB = append(seenB, a)
		mu.Unlock()
		return nil, context.DeadlineExceeded
	}
	trA := newSafeTransport(rtA, dialA)
	trB := newSafeTransport(rtB, dialB)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			req, _ := BuildRequest(context.Background(), rtA, "https://a.example/")
			trA.RoundTrip(req)
		}()
		go func() {
			defer wg.Done()
			req, _ := BuildRequest(context.Background(), rtB, "https://b.example/")
			trB.RoundTrip(req)
		}()
	}
	wg.Wait()
	for _, a := range seenA {
		if a != "93.184.216.1:443" {
			t.Fatalf("target A dialed foreign address %q", a)
		}
	}
	for _, a := range seenB {
		if a != "93.184.216.2:443" {
			t.Fatalf("target B dialed foreign address %q", a)
		}
	}
}

// A bracketed IPv6 literal must keep brackets in the wire authority —
// a bare v6 host produces an unparseable request and a silent
// INTERNAL_ERROR gap for a monitor C19 accepted.
func TestIPv6LiteralAuthority(t *testing.T) {
	rt := testResolved("2606:4700:4700::1111", 443, "2606:4700:4700::1111")
	req, err := BuildRequest(context.Background(), rt, "https://[2606:4700:4700::1111]/h")
	if err != nil {
		t.Fatalf("v6 literal must build: %v", err)
	}
	if req.URL.Host != "[2606:4700:4700::1111]" {
		t.Fatalf("authority = %q, want bracketed v6", req.URL.Host)
	}
	if req.Host != "" && req.Host != "[2606:4700:4700::1111]" {
		t.Fatalf("host = %q", req.Host)
	}
}
