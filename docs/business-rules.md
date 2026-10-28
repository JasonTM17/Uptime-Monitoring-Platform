# Business rules and implementation map

This map covers the implemented application. Start with the [user guide](user-guide.md)
for user journeys and [requirements](product-requirements.md) for scope. Linked
source and tests own executable details; a test file alone does not prove a run.

## Vocabulary and actors

| Term | Meaning |
| --- | --- |
| Monitor | An owner's public HTTP(S) target and sampling policy. |
| Health | UNKNOWN, UP or DOWN inferred from eligible observations. |
| Paused | Scheduling is stopped by a command; this is not target failure. |
| Freshness | Whether recent observations exist; stale data does not prove DOWN. |
| Incident | An observed DOWN episode, closed by recovery or an administrative reason. |
| Intent | A durable request to notify; queued does not mean delivered. |
| Generation / version | A resource concurrency token; stale writes must be re-read. |
| Security epoch | Account authority revision; an invalidating change makes older sessions stale. |

| Actor | Authority and reference |
| --- | --- |
| Visitor | Register or log in through [identity handlers](../internal/auth/handlers.go). |
| Owner | Manage only their monitors, channels and sessions; see [user guide](user-guide.md). |
| Administrator | Only permissions granted server-side; see [RBAC matrix](security/rbac-matrix.md). |
| Local operator | Bootstrap/recovery and destination verification; see [admin](runbooks/admin-recovery.md) and [notification](runbooks/notification-delivery.md) runbooks. |
| Engine / dispatcher | Record fenced observations and process durable intents; see [engine lifecycle](engine-lifecycle.md). |

## Identity and ownership

| Rule | Decision / invariant | Executable owner and regression |
| --- | --- | --- |
| BR01 Registration | Canonical email is trimmed/lowercased without provider-specific rewriting. Registration cannot assign roles, status or quota. | [Registration](../internal/auth/registration.go), [validation](../internal/auth/registration_test.go), [concurrent registration](../internal/auth/registration_integration_test.go) |
| BR02 Sessions | Revocation and absolute/idle expiry end authority. A captured principal cannot authorize a later mutation after revocation, suspension or epoch change; recheck and write share a transaction. | [Session fence](../internal/auth/middleware.go), [own sessions](../internal/auth/own_sessions_integration_test.go), [test-send denial/rollback](../internal/notification/test_handler_integration_test.go) |
| BR03 Ownership | Foreign, deleted and nonexistent owner resources share a not-found boundary. Client-supplied owner IDs grant no authority. | [Monitor repository](../internal/monitor/repository.go), [ownership tests](../internal/monitor/mutations_integration_test.go), [history isolation](../internal/analytics/api_integration_test.go), [channel isolation](../internal/notification/channels_integration_test.go) |

Browser mutations require the CSRF/origin boundary as well as a live session.
Password confirmation is a separate recent-auth gate for sensitive actions; its
timestamp cannot revive a revoked session. See [CSRF tests](../internal/auth/csrf_test.go),
[session controls](../internal/auth/own_sessions_handler.go) and
[privileged transactions](../internal/admin/stepup.go).

## Monitor lifecycle and quota

| Rule | Decision / invariant | Executable owner and regression |
| --- | --- | --- |
| BR04 Targets | Bounded public HTTP(S) checks only. Valid URL syntax is not permission to dial a private address or follow an unsafe redirect. | [Validation](../internal/monitor/validation.go), [SSRF boundary](security/ssrf-boundary.md), [destination tests](../internal/checker/destination_policy_test.go) |
| BR05 Quota | Live limits include paused monitors. Retained allocation includes tombstones. Delete can free a live slot while still consuming retained allocation; create/delete loops cannot bypass it. | [Quota-fenced repository](../internal/monitor/repository.go), [repository tests](../internal/monitor/repository_integration_test.go), [admin quota races](../internal/admin/sessions_quotas_integration_test.go) |
| BR06 Mutation | Current generation is required; a conflict leaves the requested write unapplied. Resume marks eligibility, without bypassing admission budgets. | [Lifecycle](../internal/monitor/lifecycle.go), [mutations](../internal/monitor/mutations_integration_test.go), [engine fencing](../internal/engine/fencing_integration_test.go) |

Pause/configuration changes close an open incident as CONFIG_CHANGED, and
deletion closes it as DELETED; neither is observed recovery. Editing a DOWN
monitor, or resuming it after pause, clears stale DOWN/streaks to UNKNOWN so new
failures can establish another incident. Non-DOWN streaks survive these
commands: repeated edits/resumes must not keep erasing an emerging outage.
Same-state pause/resume is a no-op. The [repository](../internal/monitor/repository.go),
[incident reasons](../internal/incident/repository.go) and
[mutation regressions](../internal/monitor/mutations_integration_test.go) own the details.

## Observations and incident decisions

BR07: only eligible evidence changes health. Consecutive-observation thresholds
avoid opening/recovering an incident on one intermittent failure.

| Current health | Observation | Result |
| --- | --- | --- |
| UNKNOWN | Eligible success | Establish UP without a recovery notification. |
| UNKNOWN or UP | Three consecutive eligible failures | Change to DOWN and open an incident. |
| DOWN | Two consecutive eligible successes | Change to UP and recover the incident. |
| DOWN | Further eligible failure | Remain DOWN without another incident-open event. |
| Any | Excluded observation | Reset streaks; preserve health and incident. |

A failed HTTP expectation or target connection can be failure evidence.
Policy rejection, cancellation and collector errors are exclusions, not proof
the target is down. Exact classification belongs to [outcomes](../internal/checker/outcomes.go),
the [reducer](../internal/incident/reducer.go) and [reducer tests](../internal/incident/reducer_test.go).

BR08: accepted result, health, incident and notification intent commit together.
Old generations, ownership epochs and stale result sequences cannot overwrite
newer authority. Interrupted work cannot fabricate DOWN. See [engine lifecycle](engine-lifecycle.md),
[finalization](../internal/engine/finalize.go), [recovery tests](../internal/engine/recovery_integration_test.go)
and the [suspension fence](../internal/engine/suspension_fence_integration_test.go).

## Notification lifecycle

| Rule | Decision / invariant | Executable owner and regression |
| --- | --- | --- |
| BR09 Recipient | Owners create metadata; operators verify/seal destinations. Binding accepts only owned, live, VERIFIED and enabled channels, atomically for the requested set. | [Channel policy](../internal/notification/channels.go), [binding tests](../internal/notification/channels_integration_test.go), [operator runbook](runbooks/notification-delivery.md) |
| BR10 Delivery | Bounded at-least-once delivery permits a duplicate after ACK loss. RECOVERY follows a SENT DOWN predecessor; DEAD blocks descendants; suppression cascades honestly. | [Runbook](runbooks/notification-delivery.md), [lease](../internal/notification/lease.go), [ambiguity tests](../internal/notification/ambiguity_integration_test.go), [causal controls](../internal/notification/operations_integration_test.go) |
| BR11 Retry | Total claims remain in attempts. Durable rate-limit refusals are deducted from send-attempt accounting; a separate refusal ceiling bounds congestion. A crash before recording refusal remains ambiguous. | [Dispatcher](../internal/notification/dispatcher.go), [lease accounting](../internal/notification/lease.go), [regression](../internal/notification/retry_budget_audit_test.go), [DB boundaries](../internal/notification/lease_integration_test.go) |

Test-send is an owner operation with recent password confirmation, binding and
rate limits. 202 means queued. Actor recheck, recent-auth read and intent write
share one transaction; rollback leaves no intent. See [handler](../internal/notification/test_handler.go)
and [denial/rollback tests](../internal/notification/test_handler_integration_test.go).
Pending-channel allocation includes deleted pending rows; delete is not a
verification shortcut.

## Statistics and retention

BR12: missing coverage is not an observed failure. Counts share the represented
window, with the partition:

    expected = valid + excluded + missed + pending

Sample uptime is successes/valid; coverage is valid/expected. Zero denominator
means no ratio, not 100%. Raw/hourly evidence must not double-count, and interval
changes must not rewrite the historical grid. See [statistics](architecture/statistics.md),
[contract tests](../internal/analytics/api_integration_test.go) and
[denominator tests](../internal/analytics/denominators_integration_test.go).

BR13: retention preserves aggregation and causal-recovery evidence. Unrolled
results, incident anchors, schedule segments and DEAD delivery rows are not
ordinary expired data. Audit history has no automatic purge in this application.
See [retention](runbooks/retention.md), [rollup tests](../internal/analytics/rollup_integration_test.go)
and [purge tests](../internal/analytics/retention_integration_test.go).

## Administration and recovery

BR14: permissions are explicit, with no implied role-name hierarchy or wildcard
future grants. Custom roles cannot delegate role-management authority.
Privileged writes require recent-auth, concurrency checks, idempotency and
transactional audit. Replay cannot bypass current session/permission checks.
Normal administration cannot remove the last active SUPER_ADMIN. CLI recovery
is a separately audited operator authority.

Use [RBAC](security/rbac-matrix.md), the [security race matrix](testing/admin-security.md),
[idempotency tests](../internal/admin/stepup_integration_test.go),
[last-admin races](../internal/admin/superadmin_integration_test.go) and
[recovery runbook](runbooks/admin-recovery.md).

Suspension revokes sessions and fences monitoring. Restore requires a new login,
preserves user-paused monitors, and cannot resurrect revoked sessions or removed
grants. An admin cannot lower quota below live usage. See [account transitions](../internal/admin/accounts.go),
[account tests](../internal/admin/accounts_integration_test.go) and [quota policy](../internal/admin/quotas.go).

## Evidence boundaries

[Testing](testing.md) distinguishes unit, PostgreSQL, browser, race and provider
checks. [Requirements](product-requirements.md) separates implemented scope from
future work. [Release evidence](releases/v0.1.0-evidence.md) binds the existing
image to its own source revision; later fixes are not included. Hosted runtime,
real Telegram receipt and benchmark capacity need separate evidence.
