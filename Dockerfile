# syntax=docker/dockerfile:1
# Release image for the uptime API (C78). Two stages: compile inside
# the pinned toolchain, ship a static binary on distroless nonroot —
# CA roots for outbound TLS, uid 65532, no shell, no package manager.
# The build context is deny-by-default (.dockerignore): only go.mod,
# go.sum, cmd/, internal/ reach the daemon.

# golang:1.27.3 index digest — verify before bumping.
FROM golang:1.27.3@sha256:f20d83a83e18dbd2a4714b8ffd4b30b287b6243962dd75608e86abcc63ba4efc AS build

WORKDIR /src
# Modules first: dependency layer caches independently of source.
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY cmd/ ./cmd/
COPY internal/ ./internal/

# Static binary: no cgo, no libc, no runtime deps. Trimpath strips
# host paths; version/revision stamp the build identity (logged at
# startup and carried in the image labels below).
ARG VERSION=dev
ARG REVISION=unknown
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
      -trimpath -buildvcs=false \
      -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" \
      -o /out/uptime-api ./cmd/api \
 && test -x /out/uptime-api

# gcr.io/distroless/static-debian12:nonroot index digest.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="uptime-platform-api" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.source="local"

COPY --from=build /out/uptime-api /usr/local/bin/uptime-api

# distroless nonroot = uid 65532, has /etc/passwd + CA roots. No
# USER directive needed beyond the tag, but set it explicitly so an
# inspect-read contract stays honest even if the base tag changes.
USER 65532:65532
EXPOSE 8080
# Direct exec: the binary is PID 1 and receives SIGTERM itself —
# a shell entrypoint would swallow the signal and break the
# bounded-shutdown contract.
ENTRYPOINT ["/usr/local/bin/uptime-api"]
