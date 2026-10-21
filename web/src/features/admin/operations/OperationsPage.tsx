import { useQuery } from "@tanstack/react-query";
import { ApiError } from "../../../lib/api/client";
import { useSession } from "../../auth/session";
import { fetchOperations } from "./queries";
import { FreshnessBadge } from "./EngineHealth";

const t = (s: string | null | undefined) =>
  s ? new Date(s).toLocaleString() : "—";

// operations:read — engine heartbeat, run pressure, outbox age and
// rollup freshness. Absent telemetry renders "absent", never "healthy".
export function OperationsPage() {
  const { user } = useSession();
  const ops = useQuery({
    queryKey: ["admin-operations", user?.id],
    queryFn: ({ signal }) => fetchOperations(signal),
    refetchInterval: 30_000,
    refetchIntervalInBackground: false,
  });
  const forbidden = ops.error instanceof ApiError && ops.error.status === 403;
  const o = ops.data;

  return (
    <div className="max-w-3xl space-y-4">
      <header>
        <h1 className="text-xl font-semibold">Operations</h1>
        <p className="mt-1 text-sm text-fg-secondary">
          Engine and delivery health — missing telemetry is reported as
          absent, never as a healthy zero.
        </p>
      </header>
      {ops.isPending ? (
        <div role="status" className="text-fg-muted">Loading operations…</div>
      ) : forbidden ? (
        <div role="alert" className="rounded border border-border bg-container p-3 text-sm text-fg-secondary">
          Your role doesn’t include{" "}
          <code className="font-mono">operations:read</code> — this section
          is denied.
        </div>
      ) : ops.isError || !o ? (
        <div role="alert" className="rounded border border-down-border bg-down-bg p-3 text-sm text-down-fg">
          Operations snapshot unavailable — a dependency may be down.{" "}
          <button type="button" onClick={() => ops.refetch()} className="underline">
            Retry
          </button>
        </div>
      ) : (
        <dl className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          <div className="rounded border border-border bg-container p-3">
            <dt className="font-mono text-[10px] uppercase tracking-wide text-fg-muted">
              Engine heartbeat
            </dt>
            <dd className="mt-1 flex items-center gap-2 text-sm text-fg">
              <FreshnessBadge value={o.engine?.freshness} />
              <span className="font-mono text-xs text-fg-muted">
                epoch {o.engine?.epoch ?? "—"}
              </span>
            </dd>
            <dd className="mt-1 font-mono text-xs text-fg-muted">
              {t(o.engine?.heartbeat_at)} · stale after{" "}
              {o.engine?.stale_after_seconds ?? "—"}s
              {o.engine?.owner_instance ? ` · ${o.engine.owner_instance}` : ""}
            </dd>
          </div>
          <div className="rounded border border-border bg-container p-3">
            <dt className="font-mono text-[10px] uppercase tracking-wide text-fg-muted">
              Runs
            </dt>
            <dd className="mt-1 text-sm text-fg">
              <span className="font-mono">{o.runs?.reserved ?? "—"}</span>{" "}
              reserved ·{" "}
              <span className="font-mono">{o.runs?.running ?? "—"}</span>{" "}
              running
            </dd>
          </div>
          <div className="rounded border border-border bg-container p-3">
            <dt className="font-mono text-[10px] uppercase tracking-wide text-fg-muted">
              Outbox
            </dt>
            <dd className="mt-1 text-sm text-fg">
              <span className="font-mono">{o.outbox?.pending ?? "—"}</span>{" "}
              pending ·{" "}
              <span className="font-mono">{o.outbox?.leased ?? "—"}</span>{" "}
              leased ·{" "}
              <span className="font-mono">{o.outbox?.dead ?? "—"}</span> dead
            </dd>
            <dd className="mt-1 font-mono text-xs text-fg-muted">
              {o.outbox?.oldest_age_seconds != null
                ? `oldest pending ${o.outbox.oldest_age_seconds}s`
                : "no pending backlog"}
            </dd>
          </div>
          <div className="rounded border border-border bg-container p-3">
            <dt className="font-mono text-[10px] uppercase tracking-wide text-fg-muted">
              Rollup
            </dt>
            <dd className="mt-1 flex items-center gap-2 text-sm text-fg">
              <FreshnessBadge value={o.rollup?.freshness} />
              <span className="font-mono text-xs text-fg-muted">
                {t(o.rollup?.last_bucket)}
              </span>
            </dd>
          </div>
        </dl>
      )}
    </div>
  );
}
