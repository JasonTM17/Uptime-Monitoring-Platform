import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { useSession } from "../auth/session";
import { fetchSummary } from "../dashboard/queries";

// The API exposes a bounded recent-incident strip on the dashboard
// summary (no global keyset endpoint exists); full per-monitor history
// lives on each monitor's detail page.
export function IncidentsPage() {
  const { user } = useSession();
  const summary = useQuery({
    queryKey: ["dashboard-summary", user?.id],
    queryFn: ({ signal }) => fetchSummary(signal),
    refetchInterval: 30_000,
    refetchIntervalInBackground: false,
  });
  const s = summary.data;
  const incidents = s?.recent_incidents ?? [];

  return (
    <div className="max-w-3xl space-y-4">
      <header>
        <h1 className="text-xl font-semibold">Incidents</h1>
        <p className="mt-1 text-sm text-fg-secondary">
          Recent incident activity across your monitors — open a monitor for
          its complete history.
        </p>
      </header>

      {summary.isPending ? (
        <div role="status" className="text-fg-muted">Loading incidents…</div>
      ) : summary.isError ? (
        <div role="alert" className="rounded border border-down-border bg-down-bg p-3 text-sm text-down-fg">
          Couldn’t load incidents.{" "}
          <button type="button" onClick={() => summary.refetch()} className="underline">
            Retry
          </button>
        </div>
      ) : (
        <>
          <p className="font-mono text-sm text-fg-secondary">
            <strong className="text-fg">{s?.open_incidents ?? 0}</strong>{" "}
            currently open
          </p>
          {incidents.length === 0 ? (
            <p className="text-sm text-fg-muted">
              No recent incidents on record.
            </p>
          ) : (
            <ul className="divide-y divide-border-subtle rounded border border-border bg-container" aria-label="Recent incidents">
              {incidents.map((i) => (
                <li key={i.id} className="flex flex-wrap items-center gap-3 px-3 py-2">
                  <Link
                    to={`/monitors/${i.monitor_id}`}
                    className="font-medium text-accent hover:underline"
                  >
                    {i.monitor_name}
                  </Link>
                  <span className="font-mono text-xs text-fg-muted">
                    opened {i.opened_at ? new Date(i.opened_at).toLocaleString() : "—"}
                  </span>
                  <span
                    className={
                      i.resolved_at
                        ? "rounded border border-absent-border bg-absent-bg px-1.5 py-0.5 font-mono text-xs text-absent-fg"
                        : "rounded border border-down-border bg-down-bg px-1.5 py-0.5 font-mono text-xs text-down-fg"
                    }
                  >
                    {i.resolved_at ? (i.close_reason ?? "resolved") : "open"}
                  </span>
                  {i.resolved_at && (
                    <span className="font-mono text-xs text-fg-muted">
                      resolved {new Date(i.resolved_at).toLocaleString()}
                    </span>
                  )}
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </div>
  );
}
