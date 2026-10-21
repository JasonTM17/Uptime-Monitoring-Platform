# Admin security race matrix

The privileged-mutation recipe's linearization order, and the
database-concurrency tests that hold it. These are deterministic
channel-barrier tests between two real connections — not Go
`-race` hunts (the CI `-race` job runs the same suite as a
secondary check for incidental shared state).

## Recipe order (the claim under test)

```
BEGIN
  1. security_anchor  FOR UPDATE      — serializes all privileged writes
  2. users            FOR UPDATE asc  — actor epoch check + subject locks
  3. sessions         FOR UPDATE      — revoke/expiry/idle checks
  4. user_roles       FOR SHARE       — grant rows pinned for the tx
  5. effective permissions reload     — no cached snapshot consulted
  6. recent-auth check (session row already locked)
  7. idempotency lookup + safe replay — AFTER authz, BEFORE business guards
  8. business guards (versions, last-superadmin, bounds)
  9. mutation + audit + idempotent record — one commit
COMMIT
```

Any of steps 1–5 denied → rollback, nothing mutates. A revocation
that arrives after a step's lock serializes *after* the commit —
the write is honestly first, never torn.

## Threat → mechanism → proof

| Threat | Fence | Proof (test) |
|---|---|---|
| Session revoked before write | session FOR UPDATE + revoked_at check | `TestRevokeWriteBarrier/revoke_before_recheck_denies_write` |
| Session revoked during write | waits on the locked row → write wins, next denied | `TestRevokeWriteBarrier/revoke_during_locked_write_serializes_after` |
| Stale actor snapshot (role removal / suspend bumped epoch) | `security_version` equality at user lock | `TestStaleEpochWriteDenied` |
| Grant deleted before guards | FOR SHARE read sees it → `ErrForbidden` | `TestPermRevokeOrdering/delete_before_guards_is_denied` |
| Grant deleted mid-flight (naive path, no epoch bump) | FOR SHARE pins grant rows → delete serializes after commit | `TestPermRevokeOrdering/delete_during_locked_write_serializes_after` |
| Conformant removal (lock + bump) during write | waits on user FOR UPDATE → write wins, next fenced | `TestRemovalSerializesBehindWrite` |
| Idempotent replay after revocation | replay lookup is step 7 — *after* actor/session/perm guards | `TestSessionRevokeBlocksReplay` |
| Two admins demote each other | anchor serializes → exactly one survivor | `TestConcurrentSuperAdminRemoval` |
| Concurrent recovery bootstrap | anchor lock in `cmd/admin bootstrap` | `TestBootstrapRace` |
| Quota write vs write | version check under user lock | `TestAdminQuotaRace` |
| Read after revocation | `AuthorizeRead` epoch check (no anchor — reads don't serialize) | `TestReadGuardEpochFence` |

## The load-bearing lock discipline

- **Anchor first, always.** Two privileged writers can never
  interleave at all; everything after is per-actor fencing.
- **Users in ascending UUID order.** Deadlock-free by construction —
  global lock order is anchor → users asc → session → grants.
- **Epoch = `security_version` stamped onto the session at issue.**
  Every revocation path (suspend, role ops, session revoke-all)
  bumps it; a stamped snapshot that no longer matches is denied at
  the user lock.
- **FOR SHARE on `user_roles` closes the perm-reload window.** The
  permission map is loaded inside the tx, but without pinning the
  grant rows a delete could land between reload and commit — the
  write would commit dead authority. FOR SHARE makes any removal
  serialize after the tx; the write is honestly first, the
  revocation second.
- **Session rechecked inside the tx** because a per-session revoke
  does *not* bump the user epoch — the user check alone can't
  fence it.
- **Replay is step 7, not step 1.** A stored idempotent response is
  reachable only *after* the current actor/session/permission
  re-verification — replay can never revive revoked authority.
- **Reads skip the anchor** (`AuthorizeRead`) so a privileged write
  never starves queries — but the same user/session/epoch/permission
  predicates are re-verified, so reads aren't a revocation
  side-channel.

## What is NOT claimed

- `FOR SHARE` pins *existing* grant rows; a brand-new grant INSERT
  for the actor can land mid-tx (harmless — it adds authority, and
  the epoch bump on the conformant path still fences stale
  snapshots).
- The 90-day audit window cap is a query bound, not a security
  boundary.
- `TestPermRevokeOrdering`'s naive delete is the adversarial floor:
  any write path that bypasses the epoch bump still cannot land
  *between* the guarded read and the commit.

### Residual seams (Wukong verdict, named not hidden)

- `AuthorizeRead` locks the actor row FOR UPDATE — a long read can
  delay that actor's revocation (liveness, not correctness).
- `now` is app-clock while revocations stamp `clock_timestamp()` —
  a request parked behind the anchor evaluates expiries at a stale
  instant (fail-closed direction only).
- The exported `WithPrivilegedTx`/`WithPrivilegedTxUsers` wrappers
  let a future caller skip reauth/idempotency — recipe discipline is
  convention, not enforcement.
- `monitorOwner` pre-reads the monitor's owner outside the guarded
  tx — safe only because `owner_id` is immutable today.
- Reads assume `conn.Begin` = READ COMMITTED; a non-default server
  isolation converts blocking into serialization failures — still
  fail-closed, never torn.
