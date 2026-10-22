# Frontend verification

How the React app (`web/`) is proven, and where the proof boundary sits.

## Gates

| Command | What it covers |
|---|---|
| `npm --prefix web run typecheck` | `tsc --noEmit` — generated schema types must line up with call sites; contract drift fails compile. |
| `npm --prefix web run api:check` | Regenerates `src/lib/api/schema.d.ts` from `docs/api/openapi.yaml` and diffs — the checked-in types must match the contract exactly. |
| `npm --prefix web run test` | Vitest + Testing Library over a stubbed `fetch` — unit-level state semantics per feature. |
| `npm --prefix web run test:e2e` | Playwright, real Chromium, dev server at `:5173`, route-intercepted API fixtures. Projects: `chromium` 1280px, `chromium-390` 390px. |
| `npm --prefix web run lint` / `build` | eslint + production bundle. |

## Evidence classes — do not conflate

- **Mocked e2e** (`web/e2e/*.spec.ts`): every route under `/api/` is
  intercepted with contract-shaped fixtures. These prove that each
  screen renders the *honest* state (denied ≠ empty, absent ≠ healthy,
  queued ≠ delivered, stale ≠ down). They prove nothing about a live
  scheduler, real Postgres, or real providers. Files carry a `MOCKED`
  header note.
- **Unit** (`web/src/**/*.test.tsx`): stubbed `fetch` + Testing
  Library. Same boundary — semantics, not live behavior.
- **Live**: auth→CRUD→admin journeys against a running API+DB, and the
  full engine DOWN→recovery→UP lifecycle, are owned by the phase-09/11
  acceptance cards. No mocked result is reported as live evidence.

## State coverage

`docs/design/state-matrix.md` lists the designed states per screen;
its "Verification coverage (the frontend verification)" section maps each state to the spec
that proves it and marks mocked/unit/manual/not-run per row.

## Accessibility

- `@axe-core/playwright` (pinned at the design-token work) runs in `e2e/shell.spec.ts`
  and `e2e/responsive-a11y.spec.ts` — zero-violation gate on login,
  dashboard, and admin overview.
- Keyboard: navigation, dialogs, filters, and audit-detail traversal
  are driven with real key events in the e2e specs. Screen-reader
  narration and focus-order aesthetics remain manual-review items.
- Responsive: page-level horizontal scroll is forbidden at
  360/390/768/1280/1440 and at 200% zoom on 390px; data tables may
  scroll inside their own region.
- `prefers-reduced-motion` is emulated and asserted to leave real
  content, not an animation-only state.

## Fixture rules for e2e authors

- Mock by **pathname predicate**, never broad globs — `url.pathname`
  `.startsWith("/api/…")`, so Vite module URLs can never be eaten.
- `/api/auth/me` and `/api/admin/overview` (the capability probe)
  decide shell identity — set them deliberately per scenario; the
  probe caches for five minutes, so register overrides before the
  first navigation.
- For "session revoked mid-use": flip a flag on the request that
  revokes, not a call counter — StrictMode may consume an aborted
  first `/me` fetch.
- 401 on any non-bootstrap query ends the session — assert the
  sign-in landing plus the expiry notice.
