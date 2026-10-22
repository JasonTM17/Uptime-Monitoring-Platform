# Testing and verification

## Local gate (runs before each phase checkpoint)

```sh
go vet ./...
go test -count=1 ./...
go build ./cmd/api
docker compose config --quiet
node scripts/check-staged-secrets.mjs          # scans staged blobs; also wired into .git/hooks/pre-commit
node scripts/check-staged-secrets.mjs --self-test
```

Budget: the whole gate should stay under ~10 minutes excluding cold image
pulls, which are recorded separately.

## Integration tests (real PostgreSQL)

DB-backed tests carry `//go:build integration` and REQUIRE
`TEST_DATABASE_URL` pointing at the **disposable** `postgres-test`
database (port 54330) — never the local data DB:

```sh
docker compose --profile db up -d postgres-test      # if not running
docker compose --profile migrate run --rm migrate-test up   # apply schema
TEST_DATABASE_URL="postgres://uptime_test@127.0.0.1:54330/uptime_test?sslmode=disable" \
  go test -count=1 -tags=integration ./internal/auth/
```

Multi-package integration runs share the ONE disposable database:
`go test` executes package binaries in parallel by default, and the
suites delete/seed shared tables. Always serialize with `-p 1`:

```sh
go test -p 1 -count=1 -tags=integration \
  ./internal/engine ./internal/incident ./internal/notification
```

## OpenAPI contract gate

`docs/api/openapi.yaml` (3.1.1) is checked by a pinned toolchain under
`tools/openapi/` — spec lint, implemented-route parity (x-future
operations excluded), example-vs-schema validation, and example
credential hygiene:

```sh
npm --prefix tools/openapi ci          # lockfile-reproducible install
node tools/openapi/check-openapi.mjs   # lint + parity + examples
node --test tools/openapi/check-openapi.test.mjs
```

Behavioral coverage includes: migration roundtrip, repository error
mapping, concurrent canonical-email registration (one account), session
create/lookup/revoke with SHA-256-only storage, owner-scoped inventory
(foreign → 404-equivalent), monitor quota fencing and generation races,
keyset pagination, pause/resume idempotence, notification-channel
pending/retained caps (tombstoned pending still counted), operator-only
destination verification (masked output, never browser-writable), and
atomic monitor→channel binding (ineligible ids fail the whole set,
same-generation writers elect exactly one), plus the full HTTP auth
flow (csrf → register → login → me → sessions → logout) through a real
`httptest` server. Fixture rows use unique emails and are deleted by
the test — no blanket truncate of unrelated rows.

CI runs the same suite in the `go-integration` job (postgres:17.11
service + pinned `migrate/migrate:v4.20.1` schema step).

## What each check proves

| Check | Proves | Does NOT prove |
|---|---|---|
| `go vet` / `gofmt` | static correctness, formatting | runtime behavior |
| `go test` (unit) | function/table-case behavior, incl. security negatives | integration, real DB, real HTTP |
| `go build` | compiles under pinned toolchain | it runs correctly |
| `docker compose config --quiet` | compose syntax + env interpolation | containers are healthy |
| `compose ps` healthy | readiness probe (`pg_isready`) passes | migration applied / app works |
| secret scanner | staged BLOBS (`git show :path`) match no secret pattern + no sensitive filenames; blocks commits via pre-commit hook | history is clean, unstaged content, binary blobs, and entropy-based secrets it has no rule for |
| `--race` (Linux `go-test` profile) | data-race absence under Linux | races on Windows host |

## CI honesty

`.github/workflows/ci.yml` pins every action by full commit SHA and grants
`contents: read` only. It defines format/vet/test/build and the scanner
self-test — nothing more. A workflow file is a definition: **CI PASS is only
claimable with a run receipt on a real commit SHA.** Live remote CI requires
owner-authorized public-history preparation first; private planning material
is excluded from cache/artifacts/logs by design.

The `go-integration` job is enabled (postgres service + migrate step)
and runs the suite under `-race`. The Linux `go-test` compose profile
also runs `-race -tags=integration` — on the Windows host, run the
integration tag explicitly as above.

## Test style

- Table-driven tests for exported behavior; parallel-safe (no `t.Setenv`,
  config loads via injected lookup).
- A security rule needs a negative case that fails before the fix and passes
  after — the test is the oracle.
- Never weaken an oracle to make a check pass; record the defect instead.

## Scanner scope notes

The staged-secrets gate reads each staged blob directly (not the diff), so
diff-prefix, quoting, attribute, and context-line tricks cannot bypass it.
It refuses sensitive filenames, scans example-suffixed files for real
secrets, decodes UTF-16 BOM text, and skips placeholder-shaped values
(`${VAR}`, `replace-me`, `<yours>`). The pre-commit hook also requires the
scanner file itself hash-identical to `HEAD` (worktree `git hash-object`
vs `HEAD:` blob vs index blob), which stays blind-proof against
`assume-unchanged`/`skip-worktree` index bits; a deliberate gate update
goes in its own commit with `SCANNER_UPDATE=1 git commit ...` and prints
the staged set.

Known residual limits, by design: unstaged file content and history;
`--no-verify`, `merge`/`rebase`/`cherry-pick`, other clones, pushes, and
host-environment tricks (`NODE_OPTIONS`, clean filters, PATH) — the hook
is local-clone defense-in-depth, so remote enforcement waits for a CI
diff-scan job (a publication-gate item); `scripts/testdata/` is the
sanctioned fixture blind spot; binary blobs without a UTF-16 BOM; secrets
under the 12-char floor, multi-line/heredoc values, real secrets
containing placeholder substrings, and shapes with no rule — review
those at publication gates, not per commit.
