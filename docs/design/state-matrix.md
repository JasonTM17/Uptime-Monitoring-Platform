# State matrix — every designed state, per screen

Legend: **L** loading · **E** empty · **X** error · **D** denied
(403) · **O** offline · **N** no-data (backend reports absence,
distinct from zero) · **S** stale (freshness past threshold) ·
**P** paused/suspended entity.

Cells: what the user sees + what they can do. "—" = not applicable.

## User scope

| Screen | L | E | X | D | O | N | S | P |
|---|---|---|---|---|---|---|---|---|
| login/register | submit spinner on the button, fields stay editable | — | inline field + server message (401 invalid / 429 limited) | — | offline banner, submit disabled | — | — | — |
| dashboard | skeleton cards | "no monitors yet" + create CTA | card-level retry | — | offline banner, last-known values dimmed | "no checks yet" per monitor | data age chip visible | paused monitors badged, excluded from "down" count |
| monitors list | skeleton rows | empty + create CTA | row-level retry | — | cached list + offline banner | — | last_checked_at age chip | paused badge |
| monitor detail | skeleton chart+stats | "no checks in window" | section-level retry (chart vs incidents independently) | owner-only: 404 treated as absent (own scope) | offline banner | stats window shrinks to `data_start` | stale freshness chip | paused: live stats frozen, resume CTA |
| monitor edit/pause | button spinner | — | inline validation (interval bounds, URL) | — | actions disabled offline | — | — | pause↔resume toggles honestly |
| channels | skeleton rows | empty + add CTA | row-level retry | — | cached + banner | "unverified" until verify completes | — | — |
| channel test | per-channel spinner + cooldown timer | — | inline error code (no provider detail) | — | disabled | — | cooldown countdown | — |
| settings/sessions | skeleton list | "this is your only session" | row retry | — | banner | — | — | revoked rows drop immediately |

## Platform scope (admin)

| Screen | L | E | X | D | O | N | S | P |
|---|---|---|---|---|---|---|---|---|
| overview | skeleton pulse | — | retry | whole-page denied state naming platform:read | banner | engine "absent" chip when no heartbeat | stale chip per section | suspended users counted separately |
| users list | skeleton rows | filtered-empty state | retry | denied page naming users:read | banner | — | — | status filter covers DISABLED |
| user detail | skeleton | — | 404→"account removed" | denied naming the missing capability | banner | "no sessions/monitors" | — | SUSPENDED badge + restore CTA |
| role catalog | skeleton | preset-only state | retry | roles:read denied | banner | — | — | builtin vs custom distinguished |
| role create/edit | form validation | — | 422 missing_permissions field chips | roles:write denied | disabled | — | conflict → reload form | — |
| operations | skeleton sections | — | per-section retry | denied naming operations:read | banner | engine absent, rollup absent | stale per section | — |
| outbox | skeleton rows | filtered-empty | retry | denied naming deliveries:read | banner | "no deliveries" | age column highlights old | — |
| outbox actions | button spinner | — | 409 not-head / not-dead inline | capability denied → buttons hidden but row still readable | disabled | — | — | — |
| global monitors | skeleton rows | filtered-empty | retry | denied naming monitors:global:read | banner | — | stale freshness | paused badge + admin-resume |
| admin monitor pause/resume | confirm dialog + spinner | — | 409 conflict inline | monitors:operate denied | disabled | — | — | — |
| audit list | skeleton rows | filtered-empty | retry | denied naming audit:read | banner | "no events in window" | — | — |
| audit detail | skeleton | — | 404→"event not found" | audit:read denied | banner | — | — | — |

## Universal states (every screen)

- **401 anywhere** → route to /login, preserve intended path, no
  cached privileged data retained on return to a different user.
- **429** → inline rate-limit note with retry hint; never a crash.
- **Mutation conflict (409 stale version)** → reload the row,
  replay the reason text, re-issue with a fresh idempotency key —
  never silently retry the same key.
- **Reduced motion** → all spinners/skeletons degrade to static
  "loading" text; charts render without animation.
- **200% zoom / 390px** → every table degrades to stacked cards;
  filters collapse into a disclosure region.

## Verification coverage

How each state class is proven. **Mocked** = Playwright route
interception over contract fixtures — proves UI state semantics, never
live engine/provider behavior. **Unit** = Vitest + Testing Library over
stubbed fetch. Live journeys land in the phase-09/11 acceptance cards.

| State | Proven by | Evidence |
|---|---|---|
| login/logout identity race (A's rows never render for B) | `e2e/identity-race.spec.ts` | mocked |
| admin nav granted per identity, re-probed after switch | `e2e/identity-race.spec.ts` | mocked |
| mid-use revoked session → sign-in + notice | `e2e/ui-states.spec.ts` | mocked |
| login inline errors (401, form preserved) | `e2e/ui-states.spec.ts` | mocked |
| offline banner + reconnect recovery | `e2e/ui-states.spec.ts` | mocked (`context.setOffline`) |
| denied ≠ empty across admin sections | `e2e/ui-states.spec.ts`, `e2e/admin-rbac.spec.ts` | mocked |
| non-admin: no admin nav + deep-link denial | `e2e/admin-rbac.spec.ts` | mocked |
| admin quota 409 explained, no silent retry | `e2e/admin-rbac.spec.ts` | mocked |
| suspended user badge + restore-only affordance | `e2e/admin-rbac.spec.ts` | mocked |
| dashboard quota / paused / stale / no-data badges | `e2e/user-monitor.spec.ts` | mocked |
| paused filter reaches the API (param, not hidden) | `e2e/user-monitor.spec.ts` | mocked |
| monitor detail no-evidence gap ("no samples", empty checks) | `e2e/user-monitor.spec.ts` | mocked |
| create form inline validation + 409 quota scope | `e2e/user-monitor.spec.ts` | mocked |
| outbox retry 202 = re-queued, suppress confirms | `e2e/admin-operations.spec.ts` | mocked |
| engine freshness stale/absent never healthy-zero | `e2e/admin-operations.spec.ts` | mocked |
| audit keyboard detail + read-only (no edit/export) | `e2e/admin-operations.spec.ts` | mocked |
| channels lifecycle, queued-not-delivered, masked destinations | `e2e/channels.spec.ts` | mocked |
| accessible chart + exact table disclosure, bounds labels | `e2e/monitor-detail.spec.ts` | mocked |
| settings keyboard dialog walkthrough | `e2e/settings.spec.ts` | mocked |
| roles catalog/ceiling/preset immutability + 409 | `e2e/admin-identity.spec.ts` | mocked |
| page-level no-horizontal-scroll 360–1440 + 200% zoom | `e2e/responsive-a11y.spec.ts` | mocked |
| axe zero-violations (dashboard + admin overview) | `e2e/responsive-a11y.spec.ts`, `e2e/shell.spec.ts` | mocked |
| keyboard reaches nav/dialogs/filters at 390px | `e2e/responsive-a11y.spec.ts` | mocked |
| reduced-motion: no animation-only state | `e2e/responsive-a11y.spec.ts` | mocked |
| CSRF-before-mutation, cache-clear on identity switch | `src/features/auth/session.test.tsx` | unit |
| per-section 403 panels (users/audit/monitors/outbox) | `src/features/admin/**/*.test.tsx` | unit |
| missing/stale/absent telemetry tri-state | `src/features/admin/operations/admin-operations.test.tsx` | unit |
| canary secrets absent from DOM **and** query cache | `src/features/admin/operations/admin-operations.test.tsx` | unit |
| revoked session mid-action fails once, honestly | `src/features/admin/operations/admin-operations.test.tsx` | unit |
| invalid cursor → invalid-filter error | `src/features/admin/operations/admin-operations.test.tsx` | unit |

### Manual-review cells (no automated proof claimed)

- Screen-reader announcements of live-region state changes — axe +
  ARIA structure verified; narration reviewed manually, not automated.
- Focus-order aesthetics inside complex dialogs — keyboard operability
  is automated; order reasonableness is manual.

### Explicitly NOT_RUN here

- Live engine DOWN→recovery→UP lifecycle against a real scheduler.
- Real Telegram/provider send success/failure.
- Real Postgres-backed API journeys (auth→CRUD→admin end to end).
  These belong to the phase-09/11 acceptance cards; mocked fixtures
  above are labeled, never presented as live proof.
