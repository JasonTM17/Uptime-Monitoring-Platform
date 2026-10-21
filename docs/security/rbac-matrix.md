# RBAC matrix

Single authoritative permission catalog (`internal/admin/permissions.go`,
seeded by migration `007_admin`). `USER` is not an admin preset: its
own-resource capabilities are domain policy derived from identity,
never from roles. A role name shown on the frontend confers nothing —
every admin route checks resolved catalog permissions server-side.

| Permission | VIEWER | SUPPORT | OPERATOR | SECURITY_ADMIN | SUPER_ADMIN |
|---|:---:|:---:|:---:|:---:|:---:|
| platform:read | ✓ | ✓ | ✓ | ✓ | ✓ |
| users:read | — | ✓ | — | ✓ | ✓ |
| users:manage | — | — | — | ✓ | ✓ |
| sessions:manage | — | — | — | ✓ | ✓ |
| quotas:manage | — | — | — | — | ✓ |
| roles:read | — | — | — | ✓ | ✓ |
| roles:manage | — | — | — | — | ✓ |
| monitors:global:read | ✓ | ✓ | ✓ | ✓ | ✓ |
| monitors:operate | — | — | ✓ | — | ✓ |
| operations:read | ✓ | ✓ | ✓ | ✓ | ✓ |
| deliveries:read | — | ✓ | ✓ | — | ✓ |
| deliveries:retry | — | — | ✓ | — | ✓ |
| deliveries:suppress | — | — | ✓ | — | ✓ |
| audit:read | — | — | — | ✓ | ✓ |

`SUPER_ADMIN` holds this exact set explicitly — no wildcard
auto-approves future permissions.

## Custom roles

- Delegation ceiling: every catalog permission **except**
  `roles:manage`. A custom role can never mint new role authority and
  can never become a protected preset.
- Read prerequisites within one role (missing → 422
  `VALIDATION_ERROR` with bounded `missing_permissions`):

  | Mutation grant | Required read grant |
  |---|---|
  | users:manage, sessions:manage, quotas:manage | users:read |
  | monitors:operate | monitors:global:read |
  | deliveries:retry, deliveries:suppress | deliveries:read |

- No implied hierarchy, no permission-string free input, no custom
  predicates/SQL/scripts.

## Invariants

- Only `SUPER_ADMIN` assigns or revokes admin roles.
- `SECURITY_ADMIN` may mutate only non-SUPER_ADMIN subjects; a
  protected subject requires `SUPER_ADMIN` plus the last-superadmin
  guard.
- `security_anchor` is the singleton serialization point for
  privileged mutations and the last-superadmin invariant.
- `audit_events` is append-only for the application role
  (SELECT/INSERT; UPDATE/DELETE/TRUNCATE revoked — enforced when the
  `uptime_app` role exists). A privileged DBA remains a trust
  boundary; this is not an external immutable log.
- Public registration always yields plain `USER`; there is no role
  input on register and no startup auto-admin.
