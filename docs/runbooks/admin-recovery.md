# Administrative bootstrap and recovery

The `admin` CLI is the controlled local-authority path for creating
the first `SUPER_ADMIN` and for regaining access after the last
administrator is locked out. It is not an HTTP surface and never runs
at process startup.

## Authority and preconditions

- Run as the operator on a host with `DATABASE_URL` set — the DSN is
  read from the environment, never from a flag (no credentials in
  shell history).
- The target must be an **existing ACTIVE user**. The tool never
  creates users; public registration always yields plain `USER`.
- Every operation locks the `security_anchor` singleton, appends an
  audit row, and is idempotent — re-running is a no-op grant.

## Bootstrap (first deploy, zero admins)

```
DATABASE_URL=... go run ./cmd/admin bootstrap \
  -email operator@example.test -reason "initial platform setup"
```

- Refuses (`bootstrap denied`) while any ACTIVE `SUPER_ADMIN` exists —
  counted under the anchor lock, so a concurrent demote cannot slip
  past.
- Two concurrent bootstraps serialize on the anchor: exactly one wins.

## Recovery (last admin lost access)

```
DATABASE_URL=... go run ./cmd/admin recover \
  -email operator@example.test -reason "maintenance: lost admin access INC-123"
```

- Grants `SUPER_ADMIN` to an existing ACTIVE user even when an admin
  already exists (unlike bootstrap).
- Revokes **every session** the target holds and bumps their security
  version — the new authority must re-authenticate.
- Run inside a declared maintenance window; do not run against a
  database you cannot audit.

## Post-recovery checks

1. Confirm the grant: `SELECT u.email, r.code FROM uptime.user_roles ur
   JOIN uptime.users u ON u.id=ur.user_id JOIN uptime.roles r ON
   r.id=ur.role_id WHERE r.code='SUPER_ADMIN';`
2. Confirm the audit row: `SELECT action, actor_kind, reason, outcome
   FROM uptime.audit_events ORDER BY created_at DESC LIMIT 5;`
3. Log in with the recovered account — old sessions are revoked.
4. Close the maintenance window and record the request ID printed by
   the CLI.

## Boundaries

- No password, token, hash or secret is accepted as a flag or echoed.
- No public-registration path can reach these functions.
- The audit row records `actor_kind='CLI'` with a nullable actor_id —
  the authority is the operator's database access, not an app session.
- If audit insert fails the grant rolls back; there is no
  "grant without audit" path.
