package notification

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestChannelValidation(t *testing.T) {
	t.Run("label bounds", func(t *testing.T) {
		if err := ValidateCreate(CreateInput{Label: "alerts"}); err != nil {
			t.Fatalf("valid label: %v", err)
		}
		for _, in := range []CreateInput{
			{Label: ""}, {Label: "   "},
			{Label: strings.Repeat("x", maxLabelRunes+1)},
		} {
			var fe *FieldError
			if err := ValidateCreate(in); !errors.As(err, &fe) {
				t.Fatalf("input %+v: want FieldError, got %v", in, err)
			}
		}
	})

	t.Run("receipt required and bounded", func(t *testing.T) {
		if err := ValidateReceipt("TICKET-42"); err != nil {
			t.Fatal(err)
		}
		if err := ValidateReceipt("  "); err == nil {
			t.Fatal("empty receipt accepted")
		}
		if err := ValidateReceipt(strings.Repeat("x", 300)); err == nil {
			t.Fatal("oversized receipt accepted")
		}
	})
}

func testRing(t *testing.T, writeV int, keyBytes ...byte) *Keyring {
	t.Helper()
	spec := ""
	for i, b := range keyBytes {
		if i > 0 {
			spec += ","
		}
		spec += fmt.Sprintf("%d=%s", i+1,
			base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, KeyLen)))
	}
	r, err := ParseKeyring(spec, fmt.Sprint(writeV))
	if err != nil {
		t.Fatalf("testRing: %v", err)
	}
	return r
}

func TestDestinationCrypto(t *testing.T) {
	ring := testRing(t, 1, 7)
	aad := []byte("aad")

	t.Run("encrypt/decrypt roundtrip", func(t *testing.T) {
		ct, v, err := ring.EncryptDestination([]byte("123456789"), aad)
		if err != nil || v != 1 {
			t.Fatal(err)
		}
		if bytes.Contains(ct, []byte("123456789")) {
			t.Fatal("ciphertext contains plaintext")
		}
		plain, err := ring.DecryptDestination(v, ct, aad)
		if err != nil || string(plain) != "123456789" {
			t.Fatalf("roundtrip: %v %q", err, plain)
		}
	})

	t.Run("wrong key fails closed", func(t *testing.T) {
		ct, v, _ := ring.EncryptDestination([]byte("999"), aad)
		other := testRing(t, 1, 3)
		if _, err := other.DecryptDestination(v, ct, aad); err == nil {
			t.Fatal("wrong key decrypted")
		}
	})

	t.Run("AAD tamper fails", func(t *testing.T) {
		ct, v, _ := ring.EncryptDestination([]byte("999"), aad)
		if _, err := ring.DecryptDestination(v, ct, []byte("other")); err == nil {
			t.Fatal("wrong AAD decrypted")
		}
	})

	t.Run("unknown version fails closed", func(t *testing.T) {
		ct, _, _ := ring.EncryptDestination([]byte("999"), aad)
		if _, err := ring.DecryptDestination(9, ct, aad); !errors.Is(err, ErrUnknownKey) {
			t.Fatalf("want ErrUnknownKey, got %v", err)
		}
	})

	t.Run("mask reveals at most last four", func(t *testing.T) {
		if got := MaskDestination("123456789"); got != "•••6789" {
			t.Fatalf("mask %q", got)
		}
		if got := MaskDestination("ab"); got != "••••" {
			t.Fatalf("short mask %q", got)
		}
		if strings.Contains(MaskDestination("123456789"), "12345") {
			t.Fatal("mask leaks prefix")
		}
	})
}
