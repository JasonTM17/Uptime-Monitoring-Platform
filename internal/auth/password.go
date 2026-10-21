package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/config"
)

// Password hashing uses Argon2id in PHC string format. Stored PHC
// parameters are NEVER trusted: verification re-checks every cost field
// against ceilings before allocating, so a tampered or hostile stored
// hash cannot trigger a memory DoS.

const (
	maxPasswordBytes = 1024 // spec byte cap, applied before any KDF work
	maxArgonMemKiB   = 256 * 1024
	maxArgonTime     = 16
	maxArgonPar      = 8
	maxSaltLen       = 64
	maxKeyLen        = 64
	minPHCFields     = 6
	// hashQueue bounds callers WAITING for a worker slot. Without it,
	// an unauthenticated KDF-amplifier (register spam) could park one
	// goroutine per request unboundedly inside Acquire.
	hashQueue = 2
)

var (
	ErrPasswordTooLong = errors.New("password exceeds maximum length")
	ErrMalformedHash   = errors.New("stored hash is malformed")
	ErrCostExceeded    = errors.New("stored hash cost exceeds policy ceiling")
)

type argonParams struct {
	memory, time, parallelism uint32
	saltLen, keyLen           uint32
}

var ErrHashBusy = errors.New("hash workers saturated")

// HashGate bounds concurrent KDF work two ways: `work` caps running
// workers (CPU/RAM bound), `wait` caps callers queued for a slot so an
// unauthenticated burst cannot park unbounded goroutines — overflow
// fails fast with ErrHashBusy (handler maps to 429) instead of blocking.
type HashGate struct {
	work chan struct{}
	wait chan struct{}
}

func NewHashGate(workers, queue int) HashGate {
	return HashGate{work: make(chan struct{}, workers), wait: make(chan struct{}, queue)}
}

// Acquire takes a queue slot (fail-fast when full) then blocks for a
// worker slot or ctx end.
func (g HashGate) Acquire(ctx context.Context) error {
	select {
	case g.wait <- struct{}{}:
	default:
		return ErrHashBusy
	}
	select {
	case g.work <- struct{}{}:
		return nil
	case <-ctx.Done():
		<-g.wait
		return ctx.Err()
	}
}

func (g HashGate) Release() { <-g.work; <-g.wait }

// Hasher computes and verifies Argon2id PHC hashes under configured
// policy. Params are immutable after construction.
type Hasher struct {
	p    argonParams
	gate HashGate
}

func NewHasher(cfg config.AuthConfig) *Hasher {
	return &Hasher{
		p: argonParams{
			memory: cfg.ArgonMemoryKiB, time: cfg.ArgonTime,
			parallelism: uint32(cfg.ArgonParallelism),
			saltLen:     cfg.ArgonSaltLen, keyLen: cfg.ArgonKeyLen,
		},
		gate: NewHashGate(cfg.HashWorkers, hashQueue),
	}
}

// HashPassword salts and hashes password, returning PHC format.
// Input is bounded, never trimmed, and the salt is crypto-random so two
// hashes of the same password always differ.
func (h *Hasher) HashPassword(ctx context.Context, password string) (string, error) {
	if len(password) > maxPasswordBytes {
		return "", ErrPasswordTooLong
	}
	if err := h.gate.Acquire(ctx); err != nil {
		return "", err
	}
	defer h.gate.Release()
	salt := make([]byte, h.p.saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, h.p.time, h.p.memory, uint8(h.p.parallelism), h.p.keyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.p.memory, h.p.time, h.p.parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword parses the stored PHC hash, enforces the cost ceiling,
// recomputes, and constant-time compares. Malformed or over-cost stored
// hashes fail closed without allocating.
func (h *Hasher) VerifyPassword(ctx context.Context, password, storedPHC string) (bool, error) {
	if len(password) > maxPasswordBytes {
		return false, ErrPasswordTooLong
	}
	p, salt, want, err := parsePHC(storedPHC)
	if err != nil {
		return false, err
	}
	if err := h.gate.Acquire(ctx); err != nil {
		return false, err
	}
	defer h.gate.Release()
	got := argon2.IDKey([]byte(password), salt, p.time, p.memory, uint8(p.parallelism), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// parsePHC decodes "$argon2id$v=19$m=...,t=...,p=...$salt$key" and
// enforces hard ceilings on every cost dimension.
func parsePHC(phc string) (argonParams, []byte, []byte, error) {
	var p argonParams
	parts := strings.Split(phc, "$")
	// "$argon2id$v=19$m=..,t=..,p=..$salt$key" splits into
	// ["", "argon2id", "v=19", "m=..,t=..,p=..", "salt", "key"]
	if len(parts) != minPHCFields || parts[0] != "" || parts[1] != "argon2id" {
		return p, nil, nil, ErrMalformedHash
	}
	var version int
	if n, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || n != 1 || version != argon2.Version {
		return p, nil, nil, ErrMalformedHash
	}
	var seen int // bitmask of required m/t/p params
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return p, nil, nil, ErrMalformedHash
		}
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return p, nil, nil, ErrMalformedHash
		}
		var bit int
		switch k {
		case "m":
			p.memory, bit = uint32(n), 1
		case "t":
			p.time, bit = uint32(n), 2
		case "p":
			p.parallelism, bit = uint32(n), 4
		default:
			return p, nil, nil, ErrMalformedHash
		}
		if seen&bit != 0 { // duplicate param — reject, never last-wins
			return p, nil, nil, ErrMalformedHash
		}
		seen |= bit
	}
	if seen != 7 {
		return p, nil, nil, ErrMalformedHash
	}
	if p.memory < 8 || p.memory > maxArgonMemKiB ||
		p.time < 1 || p.time > maxArgonTime ||
		p.parallelism < 1 || p.parallelism > maxArgonPar {
		return p, nil, nil, ErrCostExceeded
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > maxSaltLen {
		return p, nil, nil, ErrMalformedHash
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) < 16 || len(key) > maxKeyLen {
		return p, nil, nil, ErrMalformedHash
	}
	return p, salt, key, nil
}
