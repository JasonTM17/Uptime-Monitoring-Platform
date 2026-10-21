# Testing and verification

## Local gate (runs before each phase checkpoint)

```sh
go vet ./...
go test -count=1 ./...
go build ./cmd/api
docker compose config --quiet
node scripts/check-staged-secrets.mjs          # scans staged diff (run after git add)
node scripts/check-staged-secrets.mjs --self-test
```

Budget: the whole gate should stay under ~10 minutes excluding cold image
pulls, which are recorded separately.

## What each check proves

| Check | Proves | Does NOT prove |
|---|---|---|
| `go vet` / `gofmt` | static correctness, formatting | runtime behavior |
| `go test` (unit) | function/table-case behavior, incl. security negatives | integration, real DB, real HTTP |
| `go build` | compiles under pinned toolchain | it runs correctly |
| `docker compose config --quiet` | compose syntax + env interpolation | containers are healthy |
| `compose ps` healthy | readiness probe (`pg_isready`) passes | migration applied / app works |
| secret scanner | staged additions match no secret pattern + no sensitive filenames | history is clean, files outside staged set are safe |
| `--race` (Linux `go-test` profile) | data-race absence under Linux | races on Windows host |

## CI honesty

`.github/workflows/ci.yml` pins every action by full commit SHA and grants
`contents: read` only. It defines format/vet/test/build and the scanner
self-test — nothing more. A workflow file is a definition: **CI PASS is only
claimable with a run receipt on a real commit SHA.** Live remote CI requires
owner-authorized public-history preparation first; private planning material
is excluded from cache/artifacts/logs by design.

Integration (`postgres-test` + `go-test` profiles) and `-race` jobs are
enabled in the phase that owns them; race coverage belongs to the Linux
container job, not the Windows local gate.

## Test style

- Table-driven tests for exported behavior; parallel-safe (no `t.Setenv`,
  config loads via injected lookup).
- A security rule needs a negative case that fails before the fix and passes
  after — the test is the oracle.
- Never weaken an oracle to make a check pass; record the defect instead.
