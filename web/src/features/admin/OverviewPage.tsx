import { useQuery } from "@tanstack/react-query";
import { ApiError } from "../../lib/api/client";
import { useSession } from "../auth/session";
import { FreshnessBadge } from "./operations/EngineHealth";
import { fetchOverview } from "./operations/queries";

const t = (s: string | null | undefined) =>
  s ? new Date(s).toLocaleString() : "—";

// platform:read — global counts plus engine/database liveness. This is
// deliberately NOT the owner dashboard: it aggregates every owner's
// resources and reports platform health, where a missing heartbeat
// renders "absent" — never a healthy-looking zero.
export function OverviewPage() {
  const { user } = useSession();
  const overview = useQuery({
    queryKey: ["admin-overview", user?.id],
    queryFn: ({ signal }) => fetchOverview(signal),
    refetchInterval: 30_000,
    refetchIntervalInBackground: false,
  });
  const forbidden =
    overview.error instanceof ApiError && overview.error.status === 403;
  const o = overview.data;

  return (
    <div className="max-w-3xl space-y-4">
      <header>
        <h1 className="text-xl font-semibold">Admin overview</h1>
        <p className="mt-1 text-sm text-fg-secondary">
          Global scope — platform-wide counts and liveness. Each admin
          section enforces its own grant; denied sections say so rather
          than rendering empty.
        </p>
      </header>
      {overview.isPending ? (
        <div role="status" className="text-fg-muted">Loading…</div>
      ) : forbidden ? (
        <div role="alert" className="rounded border border-border bg-container p-3 text-sm text-fg-secondary">
          Your role doesn’t include{" "}
          <code className="font-mono">platform:read</code> — the overview
          is denied, not empty.
        </div>
      ) : overview.isError || !o ? (
        <div role="alert" className="rounded border border-down-border bg-down-bg p-3 text-sm text-down-fg">
          Overview unavailable — a dependency may be down. This is not a
          healthy zero.{" "}
          <button type="button" onClick={() => overview.refetch()} className="underline">
            Retry
          </button>
        </div>
      ) : (
        <>
          {o.database?.reachable === false && (
            <div role="alert" className="rounded border border-down-border bg-down-bg p-3 text-sm text-down-fg">
              The database is unreachable — counts may be stale or
              missing.
            </div>
          )}
          <dl className="grid grid-cols-2 gap-2 sm:grid-cols-3">
            <div className="rounded border border-border bg-container p-3">
              <dt className="font-mono text-[10px] uppercase tracking-wide text-fg-muted">Users</dt>
              <dd className="mt-1 font-mono text-lg">{o.users?.total ?? "—"}</dd>
              <dd className="font-mono text-xs text-fg-muted">
                {o.users?.active ?? "—"} active · {o.users?.disabled ?? "—"} disabled
              </dd>
            </div>
            <div className="rounded border border-border bg-container p-3">
              <dt className="font-mono text-[10px] uppercase tracking-wide text-fg-muted">Monitors</dt>
              <dd className="mt-1 font-mono text-lg">{o.monitors?.total ?? "—"}</dd>
              <dd className="font-mono text-xs text-fg-muted">
                {o.monitors?.up ?? "—"} up · {o.monitors?.down ?? "—"} down ·{" "}
                {o.monitors?.paused ?? "—"} paused
              </dd>
            </div>
            <div className="rounded border border-border bg-container p-3">
              <dt className="font-mono text-[10px] uppercase tracking-wide text-fg-muted">Live sessions</dt>
              <dd className="mt-1 font-mono text-lg">{o.sessions?.live ?? "—"}</dd>
            </div>
            <div className="rounded border border-border bg-container p-3">
              <dt className="font-mono text-[10px] uppercase tracking-wide text-fg-muted">Open incidents</dt>
              <dd className="mt-1 font-mono text-lg">{o.incidents?.open ?? "—"}</dd>
            </div>
            <div className="rounded border border-border bg-container p-3">
              <dt className="font-mono text-[10px] uppercase tracking-wide text-fg-muted">Outbox</dt>
              <dd className="mt-1 font-mono text-lg">{o.outbox?.pending ?? "—"}</dd>
              <dd className="font-mono text-xs text-fg-muted">
                {o.outbox?.leased ?? "—"} leased · {o.outbox?.dead ?? "—"} dead
              </dd>
            </div>
            <div className="rounded border border-border bg-container p-3">
              <dt className="font-mono text-[10px] uppercase tracking-wide text-fg-muted">
                Engine heartbeat
              </dt>
              <dd className="mt-1 flex items-center gap-2">
                <FreshnessBadge value={o.engine?.freshness} />
                <span className="font-mono text-xs text-fg-muted">
                  epoch {o.engine?.epoch ?? "—"}
                </span>
              </dd>
              <dd className="mt-1 font-mono text-xs text-fg-muted">
                {t(o.engine?.heartbeat_at)}
              </dd>
            </div>
          </dl>
        </>
      )}
    </div>
  );
}
