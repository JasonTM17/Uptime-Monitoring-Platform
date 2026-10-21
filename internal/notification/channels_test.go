package notification

import (
	"bytes"
	"errors"
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

func TestDestinationCrypto(t *testing.T) {
	key := bytes.Repeat([]byte{7}, KeyLen)

	t.Run("encrypt/decrypt roundtrip", func(t *testing.T) {
		ct, err := EncryptDestination(key, []byte("123456789"))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(ct, []byte("123456789")) {
			t.Fatal("ciphertext contains plaintext")
		}
		plain, err := DecryptDestination(key, ct)
		if err != nil || string(plain) != "123456789" {
			t.Fatalf("roundtrip: %v %q", err, plain)
		}
	})

	t.Run("wrong key fails closed", func(t *testing.T) {
		ct, _ := EncryptDestination(key, []byte("999"))
		other := bytes.Repeat([]byte{3}, KeyLen)
		if _, err := DecryptDestination(other, ct); err == nil {
			t.Fatal("wrong key decrypted")
		}
	})

	t.Run("bad key length rejected", func(t *testing.T) {
		if _, err := EncryptDestination([]byte("short"), []byte("x")); !errors.Is(err, ErrBadKey) {
			t.Fatalf("want ErrBadKey, got %v", err)
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
