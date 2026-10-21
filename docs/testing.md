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

Integration (`postgres-test` + `go-test` profiles) and `-race` jobs are
enabled in the phase that owns them; race coverage belongs to the Linux
container job, not the Windows local gate.

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
