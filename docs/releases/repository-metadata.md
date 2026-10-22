# Repository metadata receipt

State of the GitHub repository presentation surface, recorded at the
release-preparation checkpoint. This file is the readback receipt — it
describes what was observed, not what was planned.

## About

| Field | Value | Source |
|---|---|---|
| Description | `Go uptime monitoring platform with a secure HTTP checker, incident alerting, advanced admin controls, and a React dashboard.` | `gh repo view --json description` readback 2026-10-22 |
| Topics | `go`, `postgresql`, `react`, `typescript`, `uptime-monitoring`, `monitoring` | same readback |
| Homepage | *(empty)* | intentionally blank — no verified hosted URL exists yet (hosted gate not passed) |
| Visibility | `public` | readback |
| License | `licenseInfo: null` | **owner decision pending** — no LICENSE file selected |

## Tracked presentation files

- `README.md` — English; media section links the local-harness captures.
- `docs/readme-vi.md` — Vietnamese summary.
- `docs/media/` — screenshots/GIFs with `manifest.json` provenance.
- Privacy gate: `node scripts/check-docs.mjs --public-root docs --readme README.md --privacy`
  — PASS at this commit (no private plan paths, card IDs, review-agent
  names, host paths, or credential-shaped literals in public docs/media).

## Boundaries kept

- No claim of hosted deployment, registry publication, or anonymous pull:
  those gates are NOT_RUN/BLOCKED pending owner prerequisites.
- Homepage stays empty until a real deployment URL is observed.
- No repository settings beyond description/topics were mutated; branch
  protections, visibility, and collaborator state untouched.
- Badges: none added — only actual evidence may back a badge later.
