import { useQuery } from "@tanstack/react-query";
import { useSession } from "../auth/session";
import { fetchStats } from "./queries";

const DAYS = 30;
const DAY_MS = 86_400_000;

const dayKey = (d: Date) =>
  `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(
    d.getDate(),
  ).padStart(2, "0")}`;

/**
 * 30-day availability strip (Obsidian concept): one cell per local day,
 * aggregated from hourly stats buckets. Days without evidence render
 * absent — the strip never claims uptime the data does not support.
 */
export function UptimeStrip({ monitorId }: { monitorId: string }) {
  const { user } = useSession();
  const stats = useQuery({
    queryKey: ["monitor-stats", user?.id, monitorId, "30d"],
    queryFn: ({ signal }) => fetchStats(monitorId, "30d", signal),
    refetchInterval: 60_000,
    refetchIntervalInBackground: false,
  });
  const s = stats.data;
  if (!s?.series?.length) return null;

  const byDay = new Map<string, { ok: number; valid: number }>();
  for (const b of s.series) {
    if (!b.bucket_start) continue;
    const k = dayKey(new Date(b.bucket_start));
    const d = byDay.get(k) ?? { ok: 0, valid: 0 };
    d.ok += b.successes ?? 0;
    d.valid += b.valid_samples ?? 0;
    byDay.set(k, d);
  }

  const today = new Date();
  const cells: { label: string; cls: string }[] = [];
  for (let i = DAYS - 1; i >= 0; i--) {
    const day = new Date(today.getTime() - i * DAY_MS);
    const k = dayKey(day);
    const d = byDay.get(k);
    let cls = "bg-absent-bg border-absent-border";
    let label = `${k} — no evidence`;
    if (d && d.valid > 0) {
      const u = d.ok / d.valid;
      cls =
        u >= 0.999
          ? "bg-up-bg border-up-border"
          : u >= 0.95
            ? "bg-stale-bg border-stale-border"
            : "bg-down-bg border-down-border";
      label = `${k} — ${(u * 100).toFixed(1)}% of ${d.valid} samples`;
    }
    cells.push({ label, cls });
  }

  const okDays = cells.filter((c) => !c.label.includes("no evidence")).length;
  return (
    <div aria-label="30-day availability" className="mb-3 max-w-3xl">
      <div className="flex gap-px" role="list">
        {cells.map((c, i) => (
          <div
            key={i}
            role="listitem"
            title={c.label}
            className={`h-5 flex-1 rounded-[2px] border ${c.cls}`}
          />
        ))}
      </div>
      <div className="mt-1 flex justify-between font-mono text-[10px] text-fg-muted">
        <span>30 days ago</span>
        <span>{okDays} days with evidence</span>
        <span>today</span>
      </div>
    </div>
  );
}
