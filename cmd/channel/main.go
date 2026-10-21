// Command channel is the operator verification CLI for notification
// channels. Verification is deliberately NOT a browser flow: the
// operator confirms consent/ownership of the destination out-of-band
// (runbook procedure), then seals the chat ID into the channel row.
//
// Usage:
//
//	channel verify -channel <uuid> -owner <uuid> -receipt <ref>
//	  reads the destination (Telegram chat ID) from STDIN — it is
//	  never accepted as a flag, never echoed, and only the mask is
//	  printed back. Keys come from the versioned pair CHANNEL_READ_KEYRING + CHANNEL_WRITE_KEY_VERSION (legacy single CHANNEL_ENCRYPTION_KEY = implicit version 1) and
//	  DATABASE_URL come from the environment.
//
//	channel decrypt-check -channel <uuid> -owner <uuid>
//	  prints only the destination MASK — confirms the row decrypts
//	  under the configured key without revealing the destination.
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	if err := run(os.Args[1:], os.Stdin); err != nil {
		fmt.Fprintln(os.Stderr, "channel: "+err.Error())
		os.Exit(1)
	}
}

func run(args []string, stdin *os.File) error {
	if len(args) == 0 {
		return fmt.Errorf("subcommand required: verify | decrypt-check")
	}
	switch args[0] {
	case "verify":
		return verify(args[1:], stdin)
	case "decrypt-check":
		return decryptCheck(args[1:])
	default:
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

// encKeyring resolves the typed keyring (F08): prefer the versioned
// pair CHANNEL_READ_KEYRING + CHANNEL_WRITE_KEY_VERSION; accept the
// legacy single CHANNEL_ENCRYPTION_KEY as an implicit version-1
// read+write entry so existing operator runbooks keep working.
func encKeyring() (*notification.Keyring, error) {
	read := strings.TrimSpace(os.Getenv("CHANNEL_READ_KEYRING"))
	writeV := strings.TrimSpace(os.Getenv("CHANNEL_WRITE_KEY_VERSION"))
	if read != "" || writeV != "" {
		if read == "" || writeV == "" {
			return nil, fmt.Errorf("CHANNEL_READ_KEYRING and CHANNEL_WRITE_KEY_VERSION must be set together")
		}
		return notification.ParseKeyring(read, writeV)
	}
	raw := strings.TrimSpace(os.Getenv("CHANNEL_ENCRYPTION_KEY"))
	if raw == "" {
		return nil, fmt.Errorf("no channel keys configured (CHANNEL_READ_KEYRING+CHANNEL_WRITE_KEY_VERSION, or legacy CHANNEL_ENCRYPTION_KEY)")
	}
	key, err := hex.DecodeString(raw)
	if err != nil || len(key) != notification.KeyLen {
		return nil, notification.ErrBadKey
	}
	return notification.ParseKeyring(
		"1="+base64.StdEncoding.EncodeToString(key), "1")
}

func openPool(ctx context.Context) (*pgxpool.Pool, error) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return nil, fmt.Errorf("DATABASE_URL not set")
	}
	return pgxpool.New(ctx, dsn)
}

func verify(args []string, stdin *os.File) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	channel := fs.String("channel", "", "channel UUID (required)")
	owner := fs.String("owner", "", "owner user UUID (required)")
	receipt := fs.String("receipt", "", "operator receipt reference (required, runbook/ticket ref)")
	dry := fs.Bool("dry-run", false, "validate and print the mask without writing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cid, err := uuid.Parse(*channel)
	if err != nil {
		return fmt.Errorf("-channel must be a UUID")
	}
	oid, err := uuid.Parse(*owner)
	if err != nil {
		return fmt.Errorf("-owner must be a UUID")
	}
	if err := notification.ValidateReceipt(*receipt); err != nil {
		return err
	}
	ring, err := encKeyring()
	if err != nil {
		return err
	}

	// Destination from STDIN only — never a flag (would land in shell
	// history and process lists). It is echoed on a TTY but is never
	// printed back by this program — only the mask is.
	fmt.Fprint(os.Stderr, "chat ID (stdin, not printed back): ")
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && len(line) > 0) {
		return fmt.Errorf("read destination: %w", err)
	}
	dest := strings.TrimSpace(line)
	if dest == "" || len(dest) > 256 || strings.ContainsAny(dest, " \t\r\n") {
		return fmt.Errorf("destination must be a single token (1-256 chars)")
	}
	ct, _, err := ring.EncryptDestination([]byte(dest),
		notification.DestinationAAD(cid, oid, ring.WriteVersion()))
	if err != nil {
		return err
	}
	mask := notification.MaskDestination(dest)
	if *dry {
		fmt.Printf("dry-run: mask=%s key_version=%d (no write)\n", mask, ring.WriteVersion())
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := openPool(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	repo := notification.NewRepository(pool, 10*time.Second)
	c, err := repo.VerifyChannel(ctx, oid, cid, ct, mask, ring.WriteVersion(), *receipt)
	if err != nil {
		return err
	}
	// Never print the destination — mask and receipt only.
	fmt.Printf("verified: id=%s mask=%s version=%d receipt=%s\n",
		c.ID, mask, c.Version, *receipt)
	return nil
}

func decryptCheck(args []string) error {
	fs := flag.NewFlagSet("decrypt-check", flag.ContinueOnError)
	channel := fs.String("channel", "", "channel UUID (required)")
	owner := fs.String("owner", "", "owner user UUID (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cid, err := uuid.Parse(*channel)
	if err != nil {
		return fmt.Errorf("-channel must be a UUID")
	}
	oid, err := uuid.Parse(*owner)
	if err != nil {
		return fmt.Errorf("-owner must be a UUID")
	}
	ring, err := encKeyring()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := openPool(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	repo := notification.NewRepository(pool, 10*time.Second)
	c, err := repo.GetChannel(ctx, oid, cid)
	if err != nil {
		return err
	}
	if c.EncryptionKeyVersion == nil {
		return fmt.Errorf("channel has no stored key version")
	}
	plain, err := ring.DecryptDestination(*c.EncryptionKeyVersion,
		c.Ciphertext(), notification.DestinationAAD(cid, oid,
			*c.EncryptionKeyVersion))
	if err != nil {
		return fmt.Errorf("decrypt failed (wrong key version or corrupt row)")
	}
	got := notification.MaskDestination(string(plain))
	fmt.Printf("ok: mask=%s stored_mask_match=%v version=%d\n",
		got, c.DestinationMask != nil && *c.DestinationMask == got, c.Version)
	return nil
}
