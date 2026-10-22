import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { useSyncExternalStore } from "react";
import { Link } from "react-router-dom";
import { useSession } from "../auth/session";
import { MonitorTable } from "./MonitorTable";
import {
  fetchMonitors,
  fetchSummary,
  type MonitorFilters,
} from "./queries";
import { SummaryStats } from "./SummaryStats";
import { useState } from "react";

const POLL_MS = 20_000;

function useOnline() {
  return useSyncExternalStore(
    (cb) => {
      window.addEventListener("online", cb);
      window.addEventListener("offline", cb);
      return () => {
        window.removeEventListener("online", cb);
        window.removeEventListener("offline", cb);
      };
    },
    () => navigator.onLine,
  );
}

export function DashboardPage() {
  const { user } = useSession();
  const online = useOnline();
  const [filters, setFilters] = useState<MonitorFilters>({});

  const summary = useQuery({
    queryKey: ["dashboard-summary", user?.id ?? "anon"],
    queryFn: ({ signal }) => fetchSummary(signal),
    refetchInterval: POLL_MS,
    // default refetchIntervalInBackground:false pauses while hidden;
    // online networkMode pauses while offline.
    refetchIntervalInBackground: false,
  });

  const monitors = useInfiniteQuery({
    queryKey: ["monitors", user?.id ?? "anon", filters],
    queryFn: ({ signal, pageParam }) =>
      fetchMonitors(filters, pageParam, signal),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => (last.has_more ? last.next_cursor : null),
    refetchInterval: POLL_MS,
    refetchIntervalInBackground: false,
  });

  const items = monitors.data?.pages.flatMap((p) => p.items) ?? [];

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-baseline justify-between gap-4">
        <h1 className="text-lg font-semibold">Your monitors</h1>
        <span className="text-xs text-fg-muted">own scope</span>
      </div>

      {!online && (
        <div role="status" className="rounded border border-stale-border bg-stale-bg p-2 text-sm text-stale-fg">
          You’re offline — data may be stale. Polling is paused.
        </div>
      )}

      {summary.isPending ? (
        <div role="status" className="text-fg-muted">Loading summary…</div>
      ) : summary.isError ? (
        <div role="alert" className="rounded border border-down-border bg-down-bg p-3 text-sm text-down-fg">
          Couldn’t load the dashboard summary.{" "}
          <button type="button" onClick={() => summary.refetch()} className="underline">
            Retry
          </button>
        </div>
      ) : summary.data ? (
        <SummaryStats summary={summary.data} />
      ) : null}

      {summary.data?.recent_incidents && summary.data.recent_incidents.length > 0 && (
        <section aria-label="Recent incidents">
          <h2 className="mb-1 text-sm font-medium text-fg-secondary">
            Recent incidents
          </h2>
          <ul className="divide-y divide-border-subtle rounded border border-border bg-container">
            {summary.data.recent_incidents.map((i) => (
              <li key={i.id} className="flex items-center gap-3 px-3 py-1.5 text-sm">
                <span className="font-mono text-xs text-fg-muted">
                  {i.opened_at ? new Date(i.opened_at).toLocaleString() : "—"}
                </span>
                <Link
                  to={`/monitors/${i.monitor_id}`}
                  className="text-fg underline decoration-border hover:text-accent-hover"
                >
                  {i.monitor_name ?? "monitor"}
                </Link>
                <span
                  className={
                    i.resolved_at
                      ? "ml-auto rounded border border-absent-border bg-absent-bg px-1.5 py-0.5 font-mono text-xs text-absent-fg"
                      : "ml-auto rounded border border-down-border bg-down-bg px-1.5 py-0.5 font-mono text-xs text-down-fg"
                  }
                >
                  {i.resolved_at ? "resolved" : "open"}
                </span>
              </li>
            ))}
          </ul>
        </section>
      )}

      <section aria-label="Monitors">
        <div className="mb-2 flex flex-wrap items-center gap-2">
          <select
            aria-label="Filter by health"
            value={filters.health ?? ""}
            onChange={(e) =>
              setFilters((f) => ({
                ...f,
                health: (e.target.value || undefined) as MonitorFilters["health"],
              }))
            }
            className="rounded border border-border bg-container px-2 py-1 text-sm"
          >
            <option value="">All health</option>
            <option value="UP">UP</option>
            <option value="DOWN">DOWN</option>
            <option value="UNKNOWN">UNKNOWN</option>
          </select>
          <select
            aria-label="Filter by paused"
            value={filters.paused ?? ""}
            onChange={(e) =>
              setFilters((f) => ({
                ...f,
                paused: (e.target.value || undefined) as MonitorFilters["paused"],
              }))
            }
            className="rounded border border-border bg-container px-2 py-1 text-sm"
          >
            <option value="">Active + paused</option>
            <option value="false">Active only</option>
            <option value="true">Paused only</option>
          </select>
          <input
            type="search"
            aria-label="Search by name"
            placeholder="Search name…"
            value={filters.q ?? ""}
            onChange={(e) =>
              setFilters((f) => ({ ...f, q: e.target.value || undefined }))
            }
            className="min-w-0 rounded border border-border bg-inset px-2 py-1 text-sm text-fg"
          />
        </div>

        {monitors.isPending ? (
          <div role="status" className="text-fg-muted">Loading monitors…</div>
        ) : monitors.isError ? (
          <div role="alert" className="rounded border border-down-border bg-down-bg p-3 text-sm text-down-fg">
            Couldn’t load monitors.{" "}
            <button type="button" onClick={() => monitors.refetch()} className="underline">
              Retry
            </button>
          </div>
        ) : (
          <MonitorTable
            items={items}
            hasMore={monitors.hasNextPage}
            onMore={() => monitors.fetchNextPage()}
            loadingMore={monitors.isFetchingNextPage}
          />
        )}
      </section>
    </div>
  );
}
