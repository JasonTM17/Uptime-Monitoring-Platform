# Backup & restore runbook (local drill)

How to take a consistent logical backup and prove a restore into a
fresh database. The drill script automates this runbook end-to-end;
this document is the operator-facing contract it executes.

## Concepts (honest definitions)

- **RPO** — how much committed data a restore can lose. This drill
  takes the dump with the app stopped, so RPO = 0 *for this drill*.
  A live backup would be `dump_time - last_commit_before_dump`.
- **RTO** — wall time from "start restore" to "application serving the
  restored world correctly". The script measures dump, restore, and
  total seconds on this host only — **not** a hosted guarantee.
- **Restore rehearsal** — proof a dump actually restores *and the app
  invariants still hold*. A dump file existing is not evidence.

## The drill

```bash
node scripts/restore-drill.mjs --target fresh \
  --output artifacts/restore/report.json
```

What it does, in order:

1. Brings up the disposable `compose.test.yaml` world and seeds a
   deterministic dataset: a user + live session, a monitor, a
   verified notification channel (v1 ciphertext), an open incident,
   a causal outbox chain (PENDING `DOWN` → expired-LEASED `RECOVERY`),
   one completed check-run with its result ("recent charge"), and one
   `INTERRUPTED` run that must never gain a fabricated sample.
2. **Quiesces** the app (`compose stop app`) — engine and dispatcher
   disabled before the snapshot. Restoring into a running database is
   a drill anti-goal.
3. `pg_dump -Fc` into `artifacts/restore/drill.pgc` plus a manifest
   receipt (`format: uptime-restore-v1`, schema version, dump SHA-256,
   source identity, pg_dump version). The manifest is validated before
   any mutation — corrupt or wrong-version receipts refuse.
4. Restores into a **new** disposable database (`restore_drill`) —
   never the source.
5. **Pre-enable reconcile**, in the restored DB only:
   - expired outbox leases → `PENDING`
     (the same reclaim the dispatcher reaper performs);
   - **every** restored session is revoked:
     `UPDATE users SET security_version = security_version + 1` —
     a restored session token must never authenticate;
   - assert `INTERRUPTED` runs still have zero results.
6. **Repoints** the app at the restored DB with a rotated keyring
   (`read = v1+v2`, `write = v2`) — the keyring lives in the
   environment, never in the backup or the repo. Then verifies:
   - old session token → `401`;
   - fresh login → `200` (new authority only);
   - a newly created channel is sealed under key version 2
     (new writes use the current version);
   - the dispatcher drains restored `PENDING` outbox rows to `SENT`
     through the **recording** sender — never a live provider;
   - per-table counts, FK-orphan sweep, causal predecessor chain, and
     the preserved charge row.
7. Writes the report (`report.json`): manifest, per-phase timings
   (measured RTO), the receipt, and the honest limits.

## Failure rules

- Never restore over the source database.
- Never enable the dispatcher before the reconcile ran.
- Never treat a successful `pg_dump` as restore evidence.
- The manifest must validate *before* `pg_restore` runs.
- Local RTO/RPO numbers describe this host only.
- `down -v` disposes of everything the drill created; `--keep true`
  leaves the stack for inspection.

## Semantics proven by the Go lane

`go test -tags=integration ./internal/testsupport -count=1 -run \
  'TestRestoredAuthorityRevocation|TestRestoredOutboxReconciliation|TestRestoreCounts'`

- `TestRestoreCounts` — clone → identical canonical-table counts,
  zero FK orphans, schema version equal, manifest validator accepts
  only the matching receipt (corrupt / wrong-version / wrong-format
  refuse), interrupted runs carry no fabricated sample.
- `TestRestoredAuthorityRevocation` — the real `LookupSession` path:
  pre-bump the restored token authenticates; post-bump it fails
  `ErrInvalidSession`; a session stamped at the new version works.
- `TestRestoredOutboxReconciliation` — expired-LEASED reclaim to
  PENDING, causal predecessor preserved, zero fabricated deliveries.
