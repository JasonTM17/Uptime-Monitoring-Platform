# Contributing

This is a personal learning project. External contributions are not the
goal, but the repository is public and drive-by notes are welcome.

## If you found a problem

- **Bug or incorrect doc**: open an issue with a reproduction.
- **Security issue**: use [SECURITY.md](SECURITY.md) — never a public
  issue.

## Development setup

- Go (see `go.mod` for the pinned toolchain), Node 24, Docker.
- Backend: `go test ./...` (unit); integration needs the local
  PostgreSQL fixture — see `docs/runbooks/local-database.md`.
- Frontend: `npm --prefix web run dev` (proxy target defaults to
  `:8080`; `E2E_API_TARGET` overrides).
- Full composed harness + acceptance: `compose.test.yaml` and
  `scripts/accept-local.mjs`.

## Conventions that will be enforced

- Migrations are append-only; never edit an applied migration.
- The monitor engine's single-writer ownership is deliberate — don't
  add distributed coordination without measured need.
- No secrets, personal data, or private-path references in commits,
  docs, media, or reports. The docs privacy gate
  (`node scripts/check-docs.mjs --privacy`) must pass.
- Truthful status vocabulary: `PASS` / `FAIL` / `BLOCKED` / `NOT_RUN`.
  Mechanism-level results are not remote/publication/deploy claims.
