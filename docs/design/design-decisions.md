# Design decisions — console direction baseline

## Direction chosen: "Obsidian Telemetry" (locked)

One direction, locked — not a blend of samples. Source: Stitch
design system `assets/9dd72099cc3446508e235352a94e0a4f` generated
for the uptime-console brief. Rationale per the card: clear
hierarchy, restrained density, prominent health freshness.

**What it is:** deep-navy dark-first SRE console — 12-col grid,
16px max spacing rhythm, Inter + JetBrains Mono, tonal stepping +
hairline borders instead of shadows. Density serves operators who
live in the tool.

**What it is NOT:** a marketing dashboard, a blended design, or
copied generated HTML. The Stitch artifacts are concept media —
tokens map to real components in C67+; generated markup is not
the app.

## Decisions and trade-offs

| Decision | Choice | Trade-off accepted |
|---|---|---|
| Theme | Dark primary, light supported | Two palettes to keep AA — light accent darkened to #0369a1 |
| Density | Compact (28px inputs, 36px rows, ≤16px spacing) | Slightly tighter targets; mitigated: 28px min on dense, 44px on primary flows |
| Depth | Borders + tonal steps, zero ambient shadow | Flatter feel; popovers get one reserved occlusion shadow |
| Freshness | First-class — age chip on every data surface | Extra UI element per card; worth it — stale data is the product's truth |
| Status signal | Icon+label or shape+label always | More horizontal space; color is never the sole channel |
| Numerals | JetBrains Mono tabular in all metrics | Mono presence is stylistic; consistent with ops feel |
| Stale semantic | Added `status.stale`/`absent` (amber/neutral) — not in Stitch palette | One deliberate palette addition; stale must never read as error or healthy |
| Denied vs disabled | denied = amber informational, disabled = neutral can't-act-now | Two similar states kept visually distinct on purpose |

## Contrast receipt (WCAG AA — text ≥4.5, UI/large ≥3.0)

Computed by relative luminance, 2025-10-22, against
`bg.container` / `bg.canvas` pairs used in tokens.json:

- Dark: 11/11 pairs AA. Exception handled: `#f43f5e` on
  containers = 4.47 (AA-lg) → restricted to fills/borders/large
  text; down text uses `#ffb4ab` (9.68) / strong `#fb7185` (6.10).
- Light: 9/9 AA after two adjustments — accent `#0284c7`→`#0369a1`
  (5.93), focus ring reuses accent.
- Spot values: dark primary text 14.38, muted 5.85; light primary
  17.06, muted 4.55; all status foregrounds ≥4.5 in their badge
  backgrounds.

## Interactive states per mockup (annotation layer)

The generated mockups show happy-path states. The interaction
layer each must still carry (state-matrix.md is authoritative):

- **Dashboard**: card skeletons, per-card retry, offline dimming,
  paused badge, empty-state CTA.
- **Monitor detail**: chart/table pair (chart is never the only
  representation), incident banner acknowledge affordance is
  concept-only (no API — DECISION, not built), window controls.
- **Monitor list+create**: drawer focus-trap, URL field live
  validation, interval slider keyboard-adjustable, row actions
  with text labels (no icon-only destructive).
- **Admin overview**: per-section freshness chips (the STALE
  engine card is the exemplar — stale is amber, never green),
  absent = neutral "no evidence" not zero.
- **Admin users**: every mutation opens the reason+step-up+
  idempotency+expected-version dialog — mockup shows suspend;
  same dialog pattern for all five actions.
- **Admin audit**: expanded detail is read-only, JSON is
  syntax-highlighted safe_diff — no secrets by construction.

## Accessibility commitments

- Charts always pair with table alternative (screen-reader +
  no-JS fallback path).
- Keyboard order follows task order: filters → table → row
  actions → pagination. Dialogs trap focus, Escape closes.
- 390px: tables collapse to stacked cards, filters into
  disclosure. 200% zoom: layout holds, no horizontal scroll on
  primary flows.
- Reduced motion: spinners→static text, live-pulse dots→static,
  no chart animation.
- Destructive actions are labelled, never icon-only.

## Attribution / provenance

- Design system + screens: Stitch project `6396467794726005194`,
  generated 2025-10-22 from the sanitized brief
  (`stitch/brief.md`). Concept media — not licensed app code,
  not evidence of a running product.
- Fonts: Inter, JetBrains Mono (OFL, Google Fonts) — self-host or
  CDN at implementation; not embedded in tokens.
- No remote dependencies may be silently pulled into the app —
  tokens are values only.

## Open risks

- Light theme is token-verified for AA but has no Stitch mockup —
  first light render is a C7x verification item, not done today.
- Stitch `list_screens` readback returns empty; artifact URLs in
  `receipt.md` are the reference path.
