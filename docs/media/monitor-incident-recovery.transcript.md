# monitor-incident-recovery.gif — transcript

Profile: local deterministic harness (compose.test.yaml).
Flow: detail page -> forced DOWN (fixture mode) -> check lands -> DOWN state -> forced UP -> recovery checks -> dashboard UP.
Fixture: synthetic demo accounts (media-mvj3660p); fixture target 'target-public.fixture' toggled via /control.
No time-stretch: actions shown in real order; fixture waits are API-polled, not slept.
