# admin-role-and-audit.gif — transcript

Profile: local deterministic harness (compose.test.yaml).
Flow: admin users -> user detail -> suspend+reason -> audit page shows recorded action.
Fixture: synthetic demo accounts (media-mviyxr6n); fixture target 'target-public.fixture' toggled via /control.
No time-stretch: actions shown in real order; fixture waits are API-polled, not slept.
