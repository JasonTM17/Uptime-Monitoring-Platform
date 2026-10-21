# Stitch brief — uptime console (sanitized, synthetic)

Public-safe brief for generating concept mockups. All data is
synthetic — no real accounts, URLs, tokens, plan IDs, or file
paths. If a mockup needs a name it's `Example Co`, emails are
`user@example.test`, monitor targets are `https://api.example.test`.

## Product

A self-hosted uptime-monitoring web app. Two distinct experiences
sharing one shell:

- **User scope** — an account owner watches their own monitors:
  dashboard of health cards, monitor list with create/edit, a
  per-monitor detail page (uptime chart + recent checks +
  incidents), notification channel setup (Telegram-style:
  verify → test), and a settings page listing their own sessions.
- **Admin scope** — a privileged operator manages the platform:
  overview pulse (counts + engine/queue freshness), user inventory
  with suspend/restore + quota + role assignment, a role catalog
  with custom-role creation, an operations health page, a delivery
  outbox with retry/suppress, a global (redacted) monitor list,
  and an audit log.

## Visual direction

- Dense, information-first dashboard aesthetic — engineers' tool,
  not marketing page. Calm neutrals, one accent for actions,
  status colors that are never the sole signal (icons + labels too).
- Freshness is a first-class visual: every data area shows "how
  old is this" — a subtle age chip, never false-green.
- Dark mode preferred for the ops feel; light must also work.
- Typography: single sans family; tabular numerals in stat areas.

## Required mockups (priority order)

1. User dashboard — monitor health cards (UP/DOWN/paused badges,
   24h uptime %, latency sparkline, last-check age), quota meter,
   empty state variant.
2. Monitor detail — health timeline chart, stats strip
   (uptime/avg latency/incidents), recent checks table, open
   incident banner, pause/edit actions.
3. Monitor list + create form — table with health/interval/last
   check, create drawer (name, URL, interval, timeout).
4. Admin overview — counts row, engine heartbeat card showing a
   STALE state, outbox queue depth, open incidents.
5. Admin users — filterable table (search/status), row actions
   (suspend, quota, roles) with a reason+confirm dialog.
6. Admin audit — filter bar (actor/action/subject/date range),
   event table, expandable detail row.

## Explicit non-goals

- No real data, no live endpoints, no secrets of any kind.
- No "check now" button, no impersonation, no MFA screens.
- Mockups are CONCEPT artifacts — they do not substitute for
  browser evidence of the real app.
