# Screen inventory — actor / task / API / state / exit

Own scope (a signed-in user managing their monitors) and platform
scope (a privileged admin operating the platform) are deliberately
separate surfaces — an admin does not get a "better dashboard";
they get a different job's tools. Navigation is permission-aware
but is never authorization: the server denies regardless.

Capability keys below are the real permission IDs from migration
007. API routes are the implemented contract (openapi.yaml), not
aspirations — an action without an API is marked DECISION, not
invented.

## Task flows (the spine the screens exist for)

- **create → observe → incident → recover** (user): register/login
  → add monitor (name + URL + interval) → watch dashboard health
  → investigate a DOWN incident → confirm recovery / adjust.
- **deliver → suppress → retry** (user/ops): wire a verified
  channel → alerts fire on incident transitions → inspect delivery
  state → operator retries a DEAD head.
- **role → action → audit** (admin): assign/adjust a role with a
  reason + step-up → target's authority changes at next request →
  the mutation and its reason are visible in audit.
- **suspend → fence → restore** (admin): suspend a user → their
  sessions die, engine fences their monitors' results → restore →
  they may log in again; nothing is resurrected for them.

## User scope routes

| Route | Actor | Task | APIs | States | Exit condition |
|---|---|---|---|---|---|
| `/login` | any | sign in | POST /auth/login | idle, submitting, invalid, rate-limited | session cookie → dashboard |
| `/register` | any | create account | POST /auth/register | idle, submitting, taken-email, rate-limited | session cookie → dashboard |
| `/dashboard` | user | observe own fleet | GET /dashboard/ | loading, empty (no monitors), populated, stale-data, offline | answers "is anything down" |
| `/monitors` | user | list + create | GET/POST /monitors | loading, empty, form-open, validation-error, created | monitor exists + visible |
| `/monitors/{id}` | user | inspect one | GET /monitors/{id}, /checks, /incidents, /stats | loading, not-found(404→own scope hides it), paused, UP/DOWN, incident-open | understand current + recent health |
| `/monitors/{id}` edit | user | adjust | PATCH /monitors/{id}, POST /pause, /resume, DELETE | editing, saving, conflict(409), deleted | change applied or rolled back visibly |
| `/channels` | user | wire alerts | GET/POST/PATCH/DELETE /notification-channels | loading, empty, unverified, verified, verifying | ≥1 verified channel bound |
| `/channels/{id}/test` | user | prove delivery | POST /notification-channels/{id}/test | idle, cooldown(429), queued, sent, dead | a TEST delivery observed |
| `/settings` | user | sessions + account | GET /auth/me, GET/DELETE /auth/sessions, POST /auth/sessions/revoke-all, POST /auth/reauthenticate | loading, list, revoke-confirm, reauth-prompt | own sessions inventoried + revocable |

## Platform scope routes (admin)

All admin mutations carry: reason text, `Idempotency-Key`,
`expected_version`, recent-auth receipt — the screens must surface
those fields, never hide them.

| Route | Actor (capability) | Task | APIs | States | Exit condition |
|---|---|---|---|---|---|
| `/admin` | platform:read | platform pulse | GET /admin/overview | loading, fresh, stale, absent, unavailable(503) | pulse read with honest freshness |
| `/admin/users` | users:read | account inventory | GET /admin/users, /{id} | loading, filtered, paged, empty | find any account + its posture |
| `/admin/users/{id}` actions | users:write / sessions:revoke / quota:write | suspend/restore, revoke sessions, set quota, assign roles | POST /admin/users/{id}/suspend|restore|revoke-sessions, PATCH /quota, PUT /roles | view, reason-form, step-up, saving, conflict(409 stale version), done | authority changed + audit-visible |
| `/admin/roles` | roles:read / roles:write | role catalog + custom roles | GET/POST /admin/roles, PATCH /{id} | catalog, creating, missing-perms(422), done | role exists within ceiling |
| `/admin/operations` | operations:read | engine/queue health | GET /admin/operations | fresh, stale, absent, unavailable | honest ops posture |
| `/admin/outbox` | deliveries:read / retry / suppress | delivery chains | GET /admin/outbox, POST /{id}/retry, /suppress | filtered, paged, head-only actions, conflict | stream head resolved |
| `/admin/monitors` | monitors:global:read / monitors:operate | global fleet + pause/resume | GET /admin/monitors, POST /admin/monitors/{id}/pause|resume | filtered, redacted targets, confirm-reason | admin pause visible to owner too |
| `/admin/audit` | audit:read | accountability | GET /admin/audit-events, /{id} | filtered(actor/action/subject), windowed≤90d, paged, detail | any mutation explainable |

## Cross-cutting chrome

- **Shell**: logo/home, primary nav (User scope | Admin scope —
  admin items rendered only when the corresponding capability
  reads succeed; 403s hide nothing the server wouldn't also deny),
  identity chip (email + role), logout.
- **401** → bounce to /login preserving intent. **403** → inline
  denied state explaining the capability, never a silent redirect.
- **Offline/no-data/stale**: every list/detail has loading, empty,
  error, offline, and stale-freshness states explicitly designed —
  not spinner-or-nothing.
- **Forbidden on every surface**: passwords, token hashes, raw
  destinations, full URLs with query secrets, DSNs, provider
  errors, DNS internals — the API never sends them; the UI never
  invents them.

## DECISION rows (no API exists — flagged, not faked)

| Wanted | Status |
|---|---|
| "check now" manual run | DECISION — no endpoint; spec excludes it to keep engine scheduling authoritative |
| impersonate user | DECISION — deliberately absent; admin acts on records, never as the user |
| monitor public status page | DECISION — out of phase-08 scope |
| MFA/TOTP enrollment UI | DECISION — backend has no enrollment task yet; no MFA claims in UI |
