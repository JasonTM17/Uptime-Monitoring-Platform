#!/bin/sh
# Migration job entrypoint. Runs golang-migrate against DATABASE_URL.
# Destructive directions (down/drop/force) require BOTH:
#   MIGRATE_ALLOW_DESTRUCTIVE=true AND MIGRATE_TARGET=test
# so the persistent local database can never be migrated down or dropped
# through this job.
set -eu

: "${DATABASE_URL:?required}"
: "${MIGRATE_TARGET:?required (local|test)}"
: "${MIGRATE_ALLOW_DESTRUCTIVE:=false}"

ACTION="${1:-up}"

case "$ACTION" in
  up|version)
    ;;
  *)
    # Anything that can move the schema backwards, sideways, or rewrite
    # history (down, drop, goto, force, ...) is destructive: allowed only
    # against the disposable test database with an explicit opt-in.
    if [ "$MIGRATE_TARGET" != "test" ] || [ "$MIGRATE_ALLOW_DESTRUCTIVE" != "true" ]; then
      echo "refusing destructive migration '$ACTION' (target=$MIGRATE_TARGET destructive=$MIGRATE_ALLOW_DESTRUCTIVE)" >&2
      exit 2
    fi
    ;;
esac

[ "$#" -gt 0 ] && shift
exec migrate -path /migrations -database "$DATABASE_URL" "$ACTION" "$@"
