# Toolchain pins and compatibility

Pins below are versions verified to exist and, where marked, to run on the
development machine. A version listed as target but not probed is a goal, not
a compatibility claim.

## Pinned versions

| Tool | Pin | Evidence |
|---|---|---|
| Go | 1.27.3 | `GOTOOLCHAIN=go1.27.3 go version` executed: `go version go1.27.3 windows/amd64` (auto-downloaded toolchain on go1.26.5 base) |
| Node.js | 24.22.0 | Present in official nodejs.org dist index (released 2026-10-14); `.node-version` pins it |
| npm | 11.6.2+ | Ships with Node 24.x; local 11.6.2 observed |
| PostgreSQL | 17.11 | Target from planning snapshot; container image probe pending Docker engine start — NOT_RUN |
| golang-migrate | v4.20.1 | Docker Hub tag `migrate/migrate:v4.20.1` verified to exist (v-prefixed); engine probe — NOT_RUN |

## Local machine inventory (informational, not compatibility proof)

| Tool | Installed | Relationship to pin |
|---|---|---|
| Go | go1.26.5 windows/amd64 | Older base; auto toolchain resolves pinned 1.27.3 |
| Node.js | v24.12.0 | Same major as pin 24.22.0; drift recorded, upgrade recommended |
| npm | 11.6.2 | Compatible for the scripts used |
| Docker Desktop | CLI + Compose v5.6.0 installed | Engine was NOT running at probe time; container checks blocked until started |
| Git | 2.51.2.windows.1 | Sufficient |

## Known drift and incompatibilities

- Local Go base (1.26.5) is older than the pin (1.27.3). Builds rely on
  `GOTOOLCHAIN=auto` (the default), which downloads the pinned toolchain.
  If a contributor disables auto toolchain or works fully offline, the build
  fails closed instead of silently using an older Go — intended behavior.
- Local Node (24.12.0) predates the pin (24.22.0) within the same major. The
  only Node consumer so far is a dependency-free `.mjs` script, so the drift
  is benign locally, but CI and `.node-version` pin 24.22.0 exactly.
- Docker engine availability is required for PostgreSQL, migration, and
  Linux race-test containers. Until the engine runs, all container checks
  are NOT_RUN — Compose file syntax can still be validated offline.

## Prerequisites

### Windows (PowerShell)

- Go: installer from go.dev, verify `go version`; keep `GOTOOLCHAIN=auto`.
- Node.js: installer or a version manager that reads `.node-version`
  (fnm/nvm-windows reads `.nvmrc`; point it at `.node-version` or install
  `24.22.0` manually).
- Docker Desktop with the Linux engine and Compose plugin; verify
  `docker version` shows a server section, not only the client.
- Git for Windows 2.5x+.

### Linux (Debian/Ubuntu example)

- Go: tarball from go.dev into `/usr/local`, verify `go version`.
- Node.js: NodeSource or a version manager reading `.node-version`.
- Docker Engine + Compose plugin: `docker compose version` must succeed and
  `docker info` must not error.
- Git 2.5x+.

## Rules

- Never use `latest` tags for tool versions; bump pins deliberately.
- Upgrading a machine is recorded here with a rollback note — no silent
  global profile or PATH surgery.
- Compiler or runtime output is inventory, not application compatibility;
  compatibility is only claimed after the pinned version runs the relevant
  check.
