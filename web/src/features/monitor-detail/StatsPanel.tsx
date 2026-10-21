import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { BucketChart } from "../../components/BucketChart";
import { fetchStats, type StatsWindow } from "./queries";
import { useSession } from "../auth/session";

const WINDOWS: { value: StatsWindow; label: string }[] = [
  { value: "24h", label: "24h" },
  { value: "7d", label: "7d" },
  { value: "30d", label: "30d" },
];

const pct = (v: number | null | undefined) =>
  v == null ? "No evidence" : `${(v * 100).toFixed(1)}%`;
const ms = (v: number | null | undefined) =>
  v == null ? "—" : `${Math.round(v)} ms`;
const t = (s: string | null | undefined) =>
  s ? new Date(s).toLocaleString() : "—";

export function StatsPanel({ monitorId }: { monitorId: string }) {
  const { user } = useSession();
  const [window, setWindow] = useState<StatsWindow>("24h");
  const stats = useQuery({
    queryKey: ["monitor-stats", user?.id, monitorId, window],
    queryFn: ({ signal }) => fetchStats(monitorId, window, signal),
    refetchInterval: 30_000,
    refetchIntervalInBackground: false,
  });
  const s = stats.data ?? null;

  return (
    <section aria-label="Statistics" className="max-w-3xl">
      <div className="mb-2 flex flex-wrap items-center gap-3">
        <h2 className="text-sm font-medium text-fg-secondary">Statistics</h2>
        <div role="radiogroup" aria-label="Window" className="flex gap-1">
          {WINDOWS.map((w) => (
            <label
              key={w.value}
              className={`cursor-pointer rounded border px-2 py-0.5 font-mono text-xs ${
                window === w.value
                  ? "border-accent bg-accent-subtle text-fg"
                  : "border-border text-fg-secondary"
              }`}
            >
              <input
                type="radio"
                name="stats-window"
                value={w.value}
                checked={window === w.value}
                onChange={() => setWindow(w.value)}
                className="sr-only"
              />
              {w.label}
            </label>
          ))}
        </div>
      </div>

      {stats.isPending ? (
        <div role="status" className="text-fg-muted">Loading statistics…</div>
      ) : stats.isError ? (
        <div role="alert" className="rounded border border-down-border bg-down-bg p-3 text-sm text-down-fg">
          Couldn’t load statistics.{" "}
          <button type="button" onClick={() => stats.refetch()} className="underline">
            Retry
          </button>
        </div>
      ) : s ? (
        <>
          <div className="mb-2 flex flex-wrap gap-x-4 gap-y-1 font-mono text-xs text-fg-muted">
            <span>
              requested <strong className="text-fg-secondary">{t(s.window_start)}–{t(s.window_end)}</strong>
            </span>
            <span>
              represented <strong className="text-fg-secondary">{t(s.data_start)}–{t(s.data_end)}</strong>
            </span>
            <span>resolution {s.resolution ?? "none"}</span>
            <span>local time</span>
            {s.is_partial && (
              <span className="rounded border border-stale-border bg-stale-bg px-1 text-stale-fg">
                partial window
              </span>
            )}
          </div>

          <dl className="mb-3 grid grid-cols-3 gap-2 sm:grid-cols-6">
            {(
              [
                ["Sampled uptime", pct(s.sample_uptime)],
                ["Coverage", pct(s.coverage)],
                ["Avg latency", ms(s.avg_duration_ms)],
                ["Valid", String(s.valid_samples ?? 0)],
                ["Expected", String(s.expected_samples ?? 0)],
                ["Missed", String(s.missed_samples ?? 0)],
              ] as const
            ).map(([k, v]) => (
              <div key={k} className="rounded border border-border bg-container p-2">
                <dt className="font-mono text-[10px] uppercase tracking-wide text-fg-muted">
                  {k}
                </dt>
                <dd className="mt-0.5 font-mono text-sm text-fg">{v}</dd>
              </div>
            ))}
          </dl>

          {s.raw_retention_hours != null && s.raw_retention_hours < 24 && (
            <p className="mb-2 text-xs text-fg-muted">
              Raw history is retained for {s.raw_retention_hours}h on this
              profile; hourly aggregates remain available for{" "}
              {s.hourly_retention_days}d.
            </p>
          )}

          {(s.series?.length ?? 0) > 0 ? (
            <>
              <BucketChart buckets={s.series!} />
              <details className="mt-2">
                <summary className="cursor-pointer text-sm text-fg-secondary">
                  Data table ({s.series!.length} buckets)
                </summary>
                <div className="mt-1 max-h-64 overflow-auto rounded border border-border">
                  <table className="w-full text-left font-mono text-xs">
                    <thead className="sticky top-0 bg-container">
                      <tr className="border-b border-border text-fg-muted">
                        <th scope="col" className="px-2 py-1 font-medium">Bucket start (UTC)</th>
                        <th scope="col" className="px-2 py-1 font-medium">Ok</th>
                        <th scope="col" className="px-2 py-1 font-medium">Failed</th>
                        <th scope="col" className="px-2 py-1 font-medium">Excluded</th>
                        <th scope="col" className="px-2 py-1 font-medium">Uptime</th>
                        <th scope="col" className="px-2 py-1 font-medium">Avg ms</th>
                      </tr>
                    </thead>
                    <tbody>
                      {s.series!.map((b) => (
                        <tr key={b.bucket_start} className="border-b border-border-subtle last:border-0">
                          <td className="px-2 py-1">{b.bucket_start}</td>
                          <td className="px-2 py-1">{b.successes ?? 0}</td>
                          <td className="px-2 py-1">{b.failures ?? 0}</td>
                          <td className="px-2 py-1">{b.excluded_samples ?? 0}</td>
                          <td className="px-2 py-1">{pct(b.sample_uptime)}</td>
                          <td className="px-2 py-1">{ms(b.avg_duration_ms)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </details>
            </>
          ) : (
            <p className="text-sm text-fg-muted">
              No samples in this window yet — uptime is shown only when
              evidence exists.
            </p>
          )}
        </>
      ) : null}
    </section>
  );
}
