import { Link } from "react-router-dom";
import { HealthBadge } from "../../components/HealthBadge";
import { relTime, relTimeUntil } from "../../lib/format";
import type { Monitor } from "./queries";

export function MonitorTable({
  items,
  hasMore,
  onMore,
  loadingMore,
}: {
  items: Monitor[];
  hasMore: boolean;
  onMore: () => void;
  loadingMore: boolean;
}) {
  if (items.length === 0) {
    return (
      <div className="rounded border border-border bg-container p-6 text-center text-fg-muted">
        No monitors match this view.{" "}
        <Link to="/monitors" className="text-accent-hover underline">
          Create one
        </Link>
        .
      </div>
    );
  }
  return (
    <div className="overflow-x-auto rounded border border-border">
      <table className="w-full min-w-[680px] border-collapse bg-container text-left text-sm">
        <thead>
          <tr className="border-b border-border text-xs uppercase tracking-wide text-fg-muted">
            <th className="px-3 py-2 font-medium" scope="col">Name</th>
            <th className="px-3 py-2 font-medium" scope="col">Status</th>
            <th className="px-3 py-2 font-medium" scope="col">Latency</th>
            <th className="px-3 py-2 font-medium" scope="col">Interval</th>
            <th className="px-3 py-2 font-medium" scope="col">Last check</th>
            <th className="px-3 py-2 font-medium" scope="col">Next check</th>
            <th className="px-3 py-2 font-medium" scope="col">Last error</th>
          </tr>
        </thead>
        <tbody>
          {items.map((m) => (
            <tr key={m.id} className="border-b border-border-subtle last:border-0">
              <td className="px-3 py-2">
                <div className="flex items-center gap-1.5">
                  <span className="rounded border border-border bg-inset px-1 py-px font-mono text-[10px] uppercase text-fg-muted">
                    {m.method}
                  </span>
                  <Link
                    to={`/monitors/${m.id}`}
                    className="min-w-0 truncate text-fg underline decoration-border hover:text-accent-hover"
                  >
                    {m.name}
                  </Link>
                </div>
                <div className="max-w-[28ch] truncate font-mono text-xs text-fg-muted">
                  {m.target_url}
                </div>
              </td>
              <td className="px-3 py-2">
                <HealthBadge
                  health={m.health}
                  isPaused={m.is_paused}
                  freshness={m.freshness}
                />
              </td>
              <td className="px-3 py-2 font-mono text-fg-secondary">
                {m.last_response_time_ms != null ? `${m.last_response_time_ms}ms` : "—"}
              </td>
              <td className="px-3 py-2 font-mono text-fg-secondary">
                {m.interval_seconds}s
              </td>
              <td
                className="px-3 py-2 font-mono text-fg-secondary"
                title={m.last_checked_at ? new Date(m.last_checked_at).toLocaleString() : undefined}
              >
                {m.last_checked_at ? relTime(m.last_checked_at) : "—"}
              </td>
              <td
                className="px-3 py-2 font-mono text-fg-secondary"
                title={m.next_check_at ? new Date(m.next_check_at).toLocaleString() : undefined}
              >
                {m.is_paused || !m.next_check_at ? "—" : relTimeUntil(m.next_check_at)}
              </td>
              <td className="px-3 py-2 font-mono text-xs text-fg-muted">
                {m.last_error_type ?? "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {hasMore && (
        <div className="border-t border-border p-2 text-center">
          <button
            type="button"
            onClick={onMore}
            disabled={loadingMore}
            className="rounded border border-border px-3 py-1 text-fg-secondary hover:text-fg disabled:text-disabled-fg"
          >
            {loadingMore ? "Loading…" : "Load more"}
          </button>
        </div>
      )}
    </div>
  );
}
