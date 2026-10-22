import type { DashboardSummary } from "./queries";

function Tile({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="min-w-0 overflow-hidden rounded border border-border bg-container p-3">
      <div className="truncate font-mono text-xs uppercase tracking-wide text-fg-muted">
        {label}
      </div>
      <div className="mt-1 truncate font-mono text-xl text-fg">{value}</div>
      {hint && <div className="mt-0.5 break-words text-xs text-fg-muted">{hint}</div>}
    </div>
  );
}

// Uptime is a *sampled* ratio from the server — null means "no
// samples", never "100%". Coverage (monitors with evidence) is shown
// separately so absence can't masquerade as health.
export function SummaryStats({ summary }: { summary: DashboardSummary }) {
  const uptime =
    summary.sample_uptime_24h == null
      ? "No samples"
      : `${(summary.sample_uptime_24h * 100).toFixed(1)}%`;
  const q = summary.quota;
  const quotaPct =
    q && q.limit > 0 ? Math.min(100, Math.round((q.used / q.limit) * 100)) : null;

  return (
    <section aria-label="Summary" className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
      <Tile label="Monitors" value={String(summary.monitors ?? 0)} />
      <Tile
        label="Up / Down"
        value={`${summary.up ?? 0} / ${summary.down ?? 0}`}
        hint={`${summary.paused ?? 0} paused`}
      />
      <Tile
        label="24h sampled uptime"
        value={uptime}
        hint={summary.sample_uptime_24h == null ? "no check evidence yet" : "weighted by expected slots"}
      />
      <Tile label="Open incidents" value={String(summary.open_incidents ?? 0)} />
      <Tile
        label="Quota"
        value={q ? `${q.used} / ${q.limit}` : "—"}
        hint={q ? `${q.profile} · ${q.source}` : undefined}
      />
      <Tile
        label="Snapshot"
        value={summary.as_of ? new Date(summary.as_of).toLocaleTimeString() : "—"}
        hint="as of server time"
      />
      {q && quotaPct !== null && (
        <div className="col-span-full">
          <div
            role="progressbar"
            aria-label={`Monitor quota: ${q.used} of ${q.limit} used`}
            aria-valuenow={q.used}
            aria-valuemin={0}
            aria-valuemax={q.limit}
            className="h-1.5 w-full rounded bg-inset"
          >
            <div
              className="h-1.5 rounded bg-accent"
              style={{ width: `${quotaPct}%` }}
            />
          </div>
        </div>
      )}
    </section>
  );
}
