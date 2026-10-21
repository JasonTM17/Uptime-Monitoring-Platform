package notification

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fakeRT is the test-only provider: a RoundTripper that serves a
// canned response or fails with a canned error, and records the
// request so tests can assert what left the process.
type fakeRT struct {
	resp    *http.Response
	err     error
	gotBody []byte
	gotURL  string
}

func (f *fakeRT) RoundTrip(r *http.Request) (*http.Response, error) {
	f.gotURL = r.URL.String()
	if r.Body != nil {
		f.gotBody, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20))
	}
	if f.err != nil {
		return nil, f.err
	}
	f.resp.Request = r
	return f.resp, nil
}

func canned(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

const testToken = "dummy-telegram-token"

func TestTelegramSuccess(t *testing.T) {
	rt := &fakeRT{resp: canned(200,
		`{"ok":true,"result":{"message_id":42}}`)}
	d, err := NewTelegramSender(rt).Send(context.Background(),
		testToken, "12345", "monitor X is DOWN")
	if err != nil {
		t.Fatal(err)
	}
	if d.ProviderMessageID != 42 {
		t.Fatalf("message id %d", d.ProviderMessageID)
	}
	// The token may ride the request path (Bot API) but the body must
	// carry the message fields, and nothing else.
	if !strings.Contains(rt.gotURL, "/bot"+testToken+"/sendMessage") {
		t.Fatalf("unexpected request path %q", rt.gotURL)
	}
	if !strings.Contains(string(rt.gotBody), `"chat_id":"12345"`) {
		t.Fatalf("request body %s", rt.gotBody)
	}
}

func TestProviderBodyBound(t *testing.T) {
	// A runaway provider body is capped at 64KiB — no unbounded read.
	big := strings.Repeat("x", telegramBodyCap+10_000)
	rt := &fakeRT{resp: canned(200, big)}
	_, err := NewTelegramSender(rt).Send(context.Background(),
		testToken, "1", "hi")
	if err == nil {
		t.Fatal("oversized body accepted")
	}
	var se *SendError
	if !errors.As(err, &se) || !se.Retryable {
		t.Fatalf("want retryable classification, got %v", err)
	}
}

func TestProviderRedaction(t *testing.T) {
	// A transport failure surfaces no token, no URL — only class.
	rt := &fakeRT{err: fmt.Errorf("dial tcp: connection refused")}
	_, err := NewTelegramSender(rt).Send(context.Background(),
		testToken, "1", "hi")
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), testToken) ||
		strings.Contains(err.Error(), "telegram.org") ||
		strings.Contains(err.Error(), "sendMessage") {
		t.Fatalf("error leaks request identity: %v", err)
	}
	var se *SendError
	if !errors.As(err, &se) || !se.Retryable {
		t.Fatalf("transport error must be retryable, got %v", err)
	}
}

func TestTelegramClassification(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       string
		permanent  bool
		retryable  bool
		retryAfter time.Duration
	}{
		{"rate limited", 429,
			`{"ok":false,"error_code":429,"parameters":{"retry_after":7}}`,
			false, true, 7 * time.Second},
		{"provider 5xx", 502, `bad gateway`, false, true, 0},
		{"bot blocked", 403,
			`{"ok":false,"error_code":403,"description":"Forbidden: bot was blocked by the user"}`,
			true, false, 0},
		{"bad chat", 400,
			`{"ok":false,"error_code":400,"description":"chat not found"}`,
			true, false, 0},
		{"malformed ok", 200, `not json`, false, true, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rt := &fakeRT{resp: canned(c.status, c.body)}
			d, err := NewTelegramSender(rt).Send(context.Background(),
				testToken, "1", "hi")
			if err == nil {
				t.Fatal("expected error")
			}
			var se *SendError
			if !errors.As(err, &se) {
				t.Fatalf("untyped error %v", err)
			}
			if se.Permanent != c.permanent || se.Retryable != c.retryable {
				t.Fatalf("perm=%v retry=%v err=%v", se.Permanent, se.Retryable, err)
			}
			if d.RetryAfter != c.retryAfter {
				t.Fatalf("retry_after %v want %v", d.RetryAfter, c.retryAfter)
			}
		})
	}
}

func TestPendingChannelDenied(t *testing.T) {
	c := Channel{Status: StatusPending, Enabled: true}
	if c.Deliverable() {
		t.Fatal("pending channel deliverable")
	}
	c.Status = StatusVerified
	if c.Deliverable() {
		t.Fatal("verified channel without ciphertext deliverable")
	}
	c.destinationCiphertext = []byte("x")
	if !c.Deliverable() {
		t.Fatal("verified enabled channel not deliverable")
	}
	c.Enabled = false
	if c.Deliverable() {
		t.Fatal("disabled channel deliverable")
	}
	c.Enabled = true
	now := time.Now()
	c.DeletedAt = &now
	if c.Deliverable() {
		t.Fatal("tombstoned channel deliverable")
	}
	c.Status = StatusDisabled
	c.DeletedAt = nil
	if c.Deliverable() {
		t.Fatal("disabled-status channel deliverable")
	}
}

// Rotation proof: write v2, read v1+v2, restart-equivalent re-parse;
// tampered AAD, missing key, duplicate/overflow parser negatives.
func TestDestinationKeyRotationDualRead(t *testing.T) {
	k1 := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // 32 bytes
	k2 := "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
	spec := "1=" + k1 + ",2=" + k2

	ring, err := ParseKeyring(spec, "2")
	if err != nil {
		t.Fatal(err)
	}
	if ring.WriteVersion() != 2 {
		t.Fatalf("write version %d", ring.WriteVersion())
	}
	ch, ow := uuid.New(), uuid.New()

	// Rows sealed under v1 (legacy) still read after the ring rotates
	// its write version to v2 — restart is just a re-parse.
	v1ring, _ := ParseKeyring("1="+k1, "1")
	ct1, _, _ := v1ring.EncryptDestination([]byte("old-chat"),
		DestinationAAD(ch, ow, 1))
	if p, err := ring.DecryptDestination(1, ct1,
		DestinationAAD(ch, ow, 1)); err != nil || string(p) != "old-chat" {
		t.Fatalf("v1 read under v2-write ring: %v", err)
	}
	// New writes go under v2.
	ct2, ver, _ := ring.EncryptDestination([]byte("new-chat"),
		DestinationAAD(ch, ow, 2))
	if ver != 2 {
		t.Fatalf("sealed under v%d", ver)
	}
	if p, err := ring.DecryptDestination(2, ct2,
		DestinationAAD(ch, ow, 2)); err != nil || string(p) != "new-chat" {
		t.Fatalf("v2 roundtrip: %v", err)
	}
	// Re-parse = restart: same coverage.
	ring2, err := ParseKeyring(spec, "2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring2.DecryptDestination(2, ct2,
		DestinationAAD(ch, ow, 2)); err != nil {
		t.Fatalf("post-restart decrypt: %v", err)
	}
	// AAD bind: same ciphertext, wrong channel/owner/version fails.
	for _, bad := range [][16]byte{uuid.New(), ch, ow, ch} {
		_ = bad
	}
	if _, err := ring.DecryptDestination(2, ct2,
		DestinationAAD(uuid.New(), ow, 2)); err == nil {
		t.Fatal("ciphertext opened under wrong channel")
	}
	if _, err := ring.DecryptDestination(2, ct2,
		DestinationAAD(ch, uuid.New(), 2)); err == nil {
		t.Fatal("ciphertext opened under wrong owner")
	}
	if _, err := ring.DecryptDestination(1, ct2,
		DestinationAAD(ch, ow, 1)); err == nil {
		t.Fatal("ciphertext opened under wrong version")
	}
	// Missing key version fails closed.
	ring1only, _ := ParseKeyring("1="+k1, "1")
	if _, err := ring1only.DecryptDestination(2, ct2,
		DestinationAAD(ch, ow, 2)); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("missing key: %v", err)
	}
	// Parser negatives.
	for _, c := range []struct{ read, write string }{
		{"1=" + k1 + ",1=" + k2, "1"}, // duplicate version
		{"1=" + k1, "2"},              // write not in read set
		{"1=" + k1 + ",", "1"},        // trailing empty segment
		{"0=" + k1, "0"},              // version out of range
		{"5=" + k1, "5"},              // version above max
		{"1=!!!", "1"},                // not base64
		{"1=" + k1[:10], "1"},         // wrong key size
		{"", "1"},                     // empty spec
	} {
		if _, err := ParseKeyring(c.read, c.write); err == nil {
			t.Fatalf("keyring %q w=%s accepted", c.read, c.write)
		}
	}
}
