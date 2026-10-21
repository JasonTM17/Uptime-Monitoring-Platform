package notification

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// Destination encryption: AES-256-GCM, random 12-byte nonce prefixed
// to the ciphertext. encryption_key_version on the row records which
// configured key produced it — rotation keeps old rows decryptable
// under their own version (F08 max-4 read versions, later phase).

const (
	KeyLen      = 32 // AES-256
	nonceLen    = 12 // GCM standard
	KeyVersion1 = 1  // initial write version
)

var ErrBadKey = errors.New("channel encryption key must be 32 bytes")

// EncryptDestination seals a destination under key (32 bytes).
// Output = nonce || ciphertext||tag — self-contained for column store.
func EncryptDestination(key, plaintext []byte) ([]byte, error) {
	if len(key) != KeyLen {
		return nil, ErrBadKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// DecryptDestination opens a nonce-prefixed ciphertext under key.
func DecryptDestination(key, ct []byte) ([]byte, error) {
	if len(key) != KeyLen {
		return nil, ErrBadKey
	}
	if len(ct) < nonceLen {
		return nil, errors.New("ciphertext too short")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, ct[:nonceLen], ct[nonceLen:], nil)
}

// MaskDestination renders the only public form of a destination:
// last 4 characters behind a bullet. Chat IDs, tokens, and emails
// all get the same treatment — the mask never leaks length, kind,
// or structure beyond the final four symbols.
func MaskDestination(plain string) string {
	r := []rune(plain)
	if len(r) <= 4 {
		return "••••"
	}
	return fmt.Sprintf("•••%s", string(r[len(r)-4:]))
}
