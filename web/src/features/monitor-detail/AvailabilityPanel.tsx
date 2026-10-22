import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useSession } from "../auth/session";
import { fetchIncidents } from "./queries";

export function AvailabilityPanel({ monitorId }: { monitorId: string }) {
  const { user } = useSession();
  const [state, setState] = useState<"open" | "resolved" | null>(null);
  const incidents = useQuery({
    queryKey: ["monitor-incidents", user?.id, monitorId, state],
    queryFn: ({ signal }) => fetchIncidents(monitorId, state, null, signal),
  });
  const rows = incidents.data?.incidents ?? [];

  return (
    <section aria-label="Incident history" className="max-w-3xl">
      <div className="mb-2 flex flex-wrap items-center gap-3">
        <h2 className="text-sm font-medium text-fg-secondary">Incidents</h2>
        <select
          aria-label="Incident state"
          value={state ?? ""}
          onChange={(e) =>
            setState((e.target.value || null) as "open" | "resolved" | null)
          }
          className="min-w-0 rounded border border-border bg-container px-2 py-0.5 text-xs"
        >
          <option value="">All</option>
          <option value="open">Open</option>
          <option value="resolved">Resolved</option>
        </select>
      </div>
      {incidents.isPending ? (
        <div role="status" className="text-fg-muted">Loading incidents…</div>
      ) : incidents.isError ? (
        <div role="alert" className="rounded border border-down-border bg-down-bg p-3 text-sm text-down-fg">
          Couldn’t load incidents.{" "}
          <button type="button" onClick={() => incidents.refetch()} className="underline">
            Retry
          </button>
        </div>
      ) : rows.length === 0 ? (
        <p className="text-sm text-fg-muted">No incidents in this view.</p>
      ) : (
        <ul className="divide-y divide-border-subtle rounded border border-border bg-container">
          {rows.map((i) => (
            <li key={i.id} className="flex flex-wrap items-center gap-3 px-3 py-1.5 text-sm">
              <span className="font-mono text-xs text-fg-muted">
                {new Date(i.opened_at!).toLocaleString()}
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
                  → {new Date(i.resolved_at).toLocaleString()}
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
