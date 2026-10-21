// Command admin is the operator CLI for administrative bootstrap and
// recovery — the controlled local-authority path, never an HTTP
// backdoor. It requires database authority and runs only under
// operator maintenance.
//
// Usage:
//
//	admin bootstrap -email <user> -reason <why>
//	  grants SUPER_ADMIN to an existing ACTIVE user; refuses while
//	  any active SUPER_ADMIN exists. Run once after first deploy.
//
//	admin recover -email <user> -reason <why>
//	  grants SUPER_ADMIN to an existing ACTIVE user and revokes
//	  every session that user holds — the way back after the last
//	  administrator lost access.
//
// DATABASE_URL comes from the environment; no credential, token or
// secret is accepted as a flag or echoed to the console. Every
// operation locks the security anchor, appends an audit row, and is
// idempotent: re-running is a no-op grant, not a duplicate grant.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/JasonTM17/Uptime-Monitoring-Platform/internal/admin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "admin: "+err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf(`subcommand required: bootstrap | recover

  admin bootstrap -email <user> -reason <why>   grant SUPER_ADMIN when none is active
  admin recover   -email <user> -reason <why>   grant SUPER_ADMIN + revoke sessions

DATABASE_URL is read from the environment. No credential is accepted
as a flag; every operation is anchor-locked, audited and idempotent.`)
	}
	switch args[0] {
	case "bootstrap":
		return operate(args[1:], admin.BootstrapSuperAdmin)
	case "recover":
		return operate(args[1:], admin.RecoverAdministrativeAccess)
	default:
		return fmt.Errorf("unknown subcommand %q (bootstrap | recover)", args[0])
	}
}

func operate(args []string, fn func(context.Context, *pgx.Conn, string, string, string) error) error {
	fs := flag.NewFlagSet("admin", flag.ContinueOnError)
	email := fs.String("email", "", "email of an existing ACTIVE user")
	reason := fs.String("reason", "", "operator reason recorded in audit (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *email == "" {
		return fmt.Errorf("-email is required (an existing ACTIVE user; this tool never creates users)")
	}
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return fmt.Errorf("DATABASE_URL is required (environment, never a flag)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close(context.Background())

	requestID := "cli-" + uuid.NewString()
	if err := fn(ctx, conn, *email, *reason, requestID); err != nil {
		return err
	}
	// Confirmation is metadata only — never echo secrets or hashes.
	fmt.Printf("admin: %s recorded for %s (request %s)\n",
		args[0], *email, requestID)
	return nil
}
