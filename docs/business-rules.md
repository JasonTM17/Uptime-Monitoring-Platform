# Business rules and implementation map

This guide helps contributors locate the rules behind a monitoring journey. The
source and tests linked below own the exact behavior. A test in the repository is
not, by itself, evidence of a live provider or hosted deployment.

## Actors and boundaries

| Actor | Goal | Main boundary |
| --- | --- | --- |
| Monitor owner | Manage monitors, review history and configure alerts | [Monitor service](../internal/monitor/service.go), [repository](../internal/monitor/repository.go) and [ownership tests](../internal/monitor/pagination_integration_test.go) |
| Operator | Verify notification destinations and handle delivery failures | [Notification runbook](runbooks/notification-delivery.md) and [operator CLI](../cmd/channel/main.go) |
| Administrator | Manage accounts and operational controls within assigned permissions | [RBAC matrix](security/rbac-matrix.md) and [authorization](../internal/admin/authorize.go) |
| Monitoring engine | Check due targets and record transitions | [Engine lifecycle](engine-lifecycle.md) and [incident reducer](../internal/incident/reducer.go) |

## Monitor to incident

The owner creates a monitor for a public HTTP(S) target. Validation and network
policy are separate: a URL that parses successfully may still be denied at
resolution or connection time. See [monitor validation](../internal/monitor/validation.go)
and the [SSRF boundary](security/ssrf-boundary.md).

| Current health | Observation | Intended effect |
| --- | --- | --- |
| UNKNOWN | Eligible success | Establish UP without a recovery notification. |
| UNKNOWN or UP | Three consecutive eligible failures | Change to DOWN and open an incident. |
| DOWN | Two consecutive eligible successes | Change to UP and recover the incident. |
| Any | Excluded observation | Reset streaks without changing health. |

Pause and freshness are separate from health. The authoritative transition
rules and edge cases are in [reducer.go](../internal/incident/reducer.go) and
[reducer tests](../internal/incident/reducer_test.go). Reservation and
finalization use generation and ownership fences; see
[reservation](../internal/engine/reservation.go), [finalization](../internal/engine/finalize.go)
and [engine lifecycle](engine-lifecycle.md).

## Notifications and reporting

Incident changes and notification intents are persisted together. Delivery is
asynchronous, bounded and can be retried or require operator intervention.
Recovery is ordered behind its DOWN predecessor; see the
[delivery runbook](runbooks/notification-delivery.md) and
[lease tests](../internal/notification/lease_integration_test.go). A queued
message does not prove Telegram accepted or delivered it.

Availability is calculated from represented scheduled checks; missing coverage
is distinct from an observed failure. [Statistics](architecture/statistics.md)
explains the denominator and raw/hourly data boundary.

## Verification and limitations

[Testing](testing.md) describes how to run unit, integration and browser
checks with a disposable database. [Release evidence](releases/v0.1.0-evidence.md)
records the verified container digest. Neither establishes a hosted deployment
or live Telegram delivery; those require separate environment-specific evidence.
