# Notification delivery runbook

Operator reference for the durable notification pipeline. Delivery
is **bounded at-least-once**: a provider send whose ACK was lost can
duplicate the external message, but a durable intent is never lost
silently. There is no exactly-once guarantee — `event_key` dedups
the logical event, not the provider's delivery.

## Pipeline

```
incident transition
  -> finalize tx appends outbox intent (PENDING, event_key unique)
  -> dispatcher ClaimDue: SKIP LOCKED lease + attempts++ (commit)
  -> revalidate recipient fence (fresh read, no locks)
  -> rate-limit -> bounded send (5s) -> ACK SENT | reschedule | DEAD
```

Causal rule: a RECOVERY row is claimable only behind a SENT
predecessor. A PENDING or DEAD predecessor blocks it; a SUPPRESSED
predecessor *cascades* — the claim pass terminalizes the child
SUPPRESSED too, because a channel that never learned "down" must
never hear "recovered". Suppression is the authorized skip —
recorded honestly, never a fabricated send.


## Row states

| State | Meaning |
|---|---|
| PENDING | claimable when `next_attempt_at` is due and predecessor resolved |
| LEASED | a claimant holds the row until `lease_expires_at`; expiry returns it to the stream |
| SENT | provider accepted; `sent_at` recorded |
| DEAD | permanent rejection or retry/age budget exhausted — blocks descendants |
| SUPPRESSED | authorized skip (ineligible recipient or operator action); cascades to children |

## Operator controls (internal services — no public route yet)

- **RetryDeadHead(id, version)** — reset the attempt window on a
  DEAD *stream head* only: same event identity, fresh budget.
  Refused for non-DEAD rows, version conflicts, and non-heads
  (resolve the head first).
- **SuppressStream(headID)** — cascade SUPPRESSED over the head and
  every unsent descendant (LEASED rows included: the cleared lease
  token fences the racing claimant ACK). Non-head ids are refused
  with `ErrNotHead` — a RECOVERY must never be suppressed alone
  behind a live DOWN; resolve the head.
- **QueueTestNotification(owner, monitor, channel)** — persists one
  logical TEST intent after the eligibility fence: owned+bound
  monitor, VERIFIED+enabled channel, 1/min per-channel cooldown,
  bounded global outstanding set. The dispatcher delivers it through
  the normal claim path.

## Reading the queue

`ListDeliveries(owner, limit)` returns the redacted owner-scoped
projection: identity, state, attempts, `last_error_code`,
timestamps. No payload, no destination, no secrets.

Common states to act on:

- `DEAD` + `last_error_code=PERMANENT` — provider rejected (bot
  blocked, bad chat). Re-verify or disable the channel, then
  RetryDeadHead only if delivery should be re-attempted.
- `DEAD` + `RETRY_EXHAUSTED` — budget spent; check provider health
  before retrying.
- `LEASED` older than its expiry — the attempt's outcome is unknown;
  ReclaimExpired returns it to PENDING automatically.
- `PENDING` behind a DEAD predecessor — causal block; resolve the
  head (retry or suppress) rather than touching the descendant.

## Channel lifecycle (cmd/channel)

- `channel verify -channel <uuid> -owner <uuid> -receipt <ref>` —
  reads the chat ID on **stdin only**, seals it AAD-bound to
  (channel, owner, key version) under the write key, stamps the
  verification receipt. Keys come from `CHANNEL_READ_KEYRING`
  (comma-separated `version=base64key`, max 4) +
  `CHANNEL_WRITE_KEY_VERSION`; legacy `CHANNEL_ENCRYPTION_KEY` is an
  implicit version 1.
- `channel decrypt-check -channel <uuid> -owner <uuid>` — prints
  only the destination mask; proves the row opens under a configured
  key version.
