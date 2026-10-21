# Stitch connector receipt (sanitized)

Connector: `stitch` MCP — `create_project` + `generate_screen_from_text`.
Status: CAPABILITY_PRESENT. All prompts derived solely from
`brief.md` (public-safe synthetic data — no real accounts, URLs,
plan IDs, file paths, or private artifacts were sent).

- Project: `projects/6396467794726005194` — "Uptime Console —
  concept mockups" (PRIVATE)
- Design system: `assets/9dd72099cc3446508e235352a94e0a4f` —
  "Obsidian Telemetry" (DARK, Inter + JetBrains Mono,
  high-density SRE observability)
- Screens (all `screenMetadata.status: COMPLETE`, DESKTOP):
  - `screens/9ece282022eb444184c8055f67202316` — "Uptime Console —
    Dashboard" (user dashboard: health cards, quota, badges)
  - `screens/5ef9fa4d66d24a79846fdb6bc31310db` — "Storefront API —
    Monitor Detail" (uptime bar, latency chart, incident banner)
  - `screens/246488c56f7e4f889e974668844ccc40` — "Monitors —
    Uptime Console" (list + create drawer, redacted targets)
  - `screens/58fc6dabf5a64ef2acc0b5c48aea7b92` — "Platform
    Overview — Admin Console" (counts, STALE engine heartbeat)
  - `screens/32caeada5a064f75b959b9e3cd870ed6` — "Platform Users —
    Admin Console" (inventory + suspend dialog w/ reason fields)
  - `screens/8a30ab320b084d87b6f4ce284915888b` — "Audit Events —
    Admin Console" (filters + expanded safe_diff detail)

Known connector quirks: `list_screens` returns `{}` despite the
screens existing (readback via generation response names instead).
`get_screen`/`download_file` were not exercised — artifact URLs
returned in each generation response are the readback path.

These are CONCEPT artifacts for design review. They prove nothing
about the running app — browser evidence comes from the real SPA
in later cards.
