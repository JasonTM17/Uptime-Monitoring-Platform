import { Link } from "react-router-dom";
import { HealthBadge } from "../../components/HealthBadge";
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
      <table className="w-full min-w-[560px] border-collapse bg-container text-left text-sm">
        <thead>
          <tr className="border-b border-border text-xs uppercase tracking-wide text-fg-muted">
            <th className="px-3 py-2 font-medium" scope="col">Name</th>
            <th className="px-3 py-2 font-medium" scope="col">Status</th>
            <th className="px-3 py-2 font-medium" scope="col">Interval</th>
            <th className="px-3 py-2 font-medium" scope="col">Last check</th>
            <th className="px-3 py-2 font-medium" scope="col">Last error</th>
          </tr>
        </thead>
        <tbody>
          {items.map((m) => (
            <tr key={m.id} className="border-b border-border-subtle last:border-0">
              <td className="px-3 py-2">
                <Link
                  to={`/monitors/${m.id}`}
                  className="text-fg underline decoration-border hover:text-accent-hover"
                >
                  {m.name}
                </Link>
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
                {m.interval_seconds}s
              </td>
              <td className="px-3 py-2 font-mono text-fg-secondary">
                {m.last_checked_at
                  ? new Date(m.last_checked_at).toLocaleTimeString()
                  : "—"}
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
