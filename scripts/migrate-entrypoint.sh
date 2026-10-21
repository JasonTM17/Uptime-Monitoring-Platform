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
  up|version|goto|force)
    ;;
  down|drop)
    if [ "$MIGRATE_TARGET" != "test" ] || [ "$MIGRATE_ALLOW_DESTRUCTIVE" != "true" ]; then
      echo "refusing destructive migration '$ACTION' (target=$MIGRATE_TARGET destructive=$MIGRATE_ALLOW_DESTRUCTIVE)" >&2
      exit 2
    fi
    ;;
  *)
    echo "unknown migration action: $ACTION" >&2
    exit 2
    ;;
esac

exec migrate -path /migrations -database "$DATABASE_URL" "$ACTION" "${2:-}"
