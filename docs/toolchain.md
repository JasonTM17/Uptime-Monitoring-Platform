# Toolchain pins and compatibility

The project records toolchain pins in executable configuration. Installed
versions and runtime availability vary by machine; verify them locally.

## Pinned versions

| Tool | Pin | Source |
|---|---|---|
| Go | 1.27.3 | [go.mod](../go.mod) |
| Node.js | 24.22.0 | [.node-version](../.node-version) |
| PostgreSQL | 17.11 | [compose.yaml](../compose.yaml) |
| golang-migrate | v4.20.1 | [compose.yaml](../compose.yaml) |

Go's automatic toolchain selection may download the version in `go.mod`;
offline contributors need that version installed. Docker's running Linux
engine is required for the database, migrations and container test services.

## Prerequisites

### Windows (PowerShell)

- Go: installer from go.dev, verify `go version`; keep `GOTOOLCHAIN=auto`.
- Node.js: installer or a version manager that reads `.node-version`
  (fnm/nvm-windows reads `.nvmrc`; point it at `.node-version` or install
  `24.22.0` manually).
- Docker Desktop with the Linux engine and Compose plugin; verify
  `docker version` shows a server section, not only the client.
- Git for Windows.

### Linux (Debian/Ubuntu example)

- Go: tarball from go.dev into `/usr/local`, verify `go version`.
- Node.js: NodeSource or a version manager reading `.node-version`.
- Docker Engine + Compose plugin: `docker compose version` must succeed and
  `docker info` must not error.
- Git.

## Rules

- Never use `latest` tags for tool versions; bump pins deliberately.
- Compiler or runtime output is inventory, not application compatibility;
  compatibility is only claimed after the pinned version runs the relevant
  check.
