package notification

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Destination encryption: AES-256-GCM, random 12-byte nonce prefixed
// to the ciphertext, and AAD binding the record to (channel, owner,
// key version) — a ciphertext moved to another row or owner cannot
// open. Rows record which configured key version produced them, so
// rotation keeps old rows decryptable under their own version.
//
// Key material comes from a typed keyring (F08): CHANNEL_READ_KEYRING
// is "version=base64key,version=base64key" with at most four entries,
// and CHANNEL_WRITE_KEY_VERSION names the one version new writes use.
// A write version missing from the read set is a configuration error
// — never silently encrypt under a key that cannot be read back.

const (
	KeyLen        = 32 // AES-256
	nonceLen      = 12 // GCM standard
	MaxKeyVersion = 4  // F08 cap on live read versions
)

var (
	ErrBadKey       = errors.New("channel encryption key must be 32 bytes")
	ErrKeyring      = errors.New("invalid channel keyring")
	ErrUnknownKey   = errors.New("no key configured for stored key version")
	ErrKeyringRange = errors.New("keyring exceeds four live versions")
)

// Keyring is the parsed, validated read/write key set. Zero values
// are invalid — always construct via ParseKeyring.
type Keyring struct {
	keys   map[int][]byte
	writeV int
}

// ParseKeyring validates the two environment values. readSpec is
// comma-separated "version=base64(32-byte-key)" pairs; writeSpec is a
// single version integer that must be present in the read set.
// Rejects duplicates, non-integer or out-of-range versions, missing
// write versions, wrong key sizes, and trailing/empty segments.
func ParseKeyring(readSpec, writeSpec string) (*Keyring, error) {
	writeV, err := strconv.Atoi(strings.TrimSpace(writeSpec))
	if err != nil || writeV < 1 || writeV > MaxKeyVersion {
		return nil, fmt.Errorf("%w: write version %q", ErrKeyring, writeSpec)
	}
	keys := map[int][]byte{}
	for _, seg := range strings.Split(readSpec, ",") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			return nil, fmt.Errorf("%w: empty segment", ErrKeyring)
		}
		ver, raw, ok := strings.Cut(seg, "=")
		if !ok || ver == "" || raw == "" {
			return nil, fmt.Errorf("%w: segment %q", ErrKeyring, seg)
		}
		v, err := strconv.Atoi(strings.TrimSpace(ver))
		if err != nil || v < 1 || v > MaxKeyVersion {
			return nil, fmt.Errorf("%w: version %q", ErrKeyring, ver)
		}
		if _, dup := keys[v]; dup {
			return nil, fmt.Errorf("%w: duplicate version %d", ErrKeyring, v)
		}
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("%w: version %d not base64", ErrKeyring, v)
		}
		if len(key) != KeyLen {
			return nil, fmt.Errorf("%w: version %d", ErrBadKey, v)
		}
		keys[v] = key
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: no read keys", ErrKeyring)
	}
	if len(keys) > MaxKeyVersion {
		return nil, ErrKeyringRange
	}
	if _, ok := keys[writeV]; !ok {
		return nil, fmt.Errorf("%w: write version %d not in read set",
			ErrKeyring, writeV)
	}
	return &Keyring{keys: keys, writeV: writeV}, nil
}

// WriteVersion is the version new ciphertext is sealed under.
func (k *Keyring) WriteVersion() int { return k.writeV }

// Versions lists configured versions (tests and startup checks use
// it to prove live coverage; secrets never surface).
func (k *Keyring) Versions() []int {
	vs := make([]int, 0, len(k.keys))
	for v := range k.keys {
		vs = append(vs, v)
	}
	sort.Ints(vs)
	return vs
}

// EncryptDestination seals plaintext under the ring's write version,
// bound to aad. Returns the ciphertext and the version used.
func (k *Keyring) EncryptDestination(plaintext, aad []byte) ([]byte, int, error) {
	ct, err := encrypt(k.keys[k.writeV], plaintext, aad)
	if err != nil {
		return nil, 0, err
	}
	return ct, k.writeV, nil
}

// DecryptDestination opens ct under the key named by version — the
// row's own encryption_key_version, never the write default.
func (k *Keyring) DecryptDestination(version int, ct, aad []byte) ([]byte, error) {
	key, ok := k.keys[version]
	if !ok {
		return nil, ErrUnknownKey
	}
	return decrypt(key, ct, aad)
}

func encrypt(key, plaintext, aad []byte) ([]byte, error) {
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
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

func decrypt(key, ct, aad []byte) ([]byte, error) {
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
	return gcm.Open(nil, ct[:nonceLen], ct[nonceLen:], aad)
}

// DestinationAAD builds the per-record associated data binding the
// ciphertext to exactly (channel, owner, key version). Hex-free raw
// bytes — collisions between textual forms are impossible.
func DestinationAAD(channelID, ownerID [16]byte, version int) []byte {
	aad := make([]byte, 0, 16+16+4)
	aad = append(aad, channelID[:]...)
	aad = append(aad, ownerID[:]...)
	return append(aad, byte(version>>24), byte(version>>16),
		byte(version>>8), byte(version))
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
	return fmt.Sprintf("•••%s",
		string(r[len(r)-4:]))
}
