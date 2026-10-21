import { useInfiniteQuery } from "@tanstack/react-query";
import { useState } from "react";
import { ApiError } from "../../../lib/api/client";
import { useSession } from "../../auth/session";
import { AdminActionDialog, type AdminAction } from "../AdminActionDialog";
import {
  fetchGlobalMonitors,
  setMonitorPaused,
  type AdminMonitorRow,
  type MonitorFilters,
} from "./queries";

// monitors:global:read — every owner's monitor, targets reduced to
// scheme+host server-side. Pause/resume runs under monitors:operate
// through the privileged-action dialog (reason + generation fence +
// idempotency + step-up).
export function GlobalMonitorsPage() {
  const { user } = useSession();
  const [owner, setOwner] = useState("");
  const [paused, setPaused] = useState<"" | "true" | "false">("");
  const [health, setHealth] = useState<"" | "UP" | "DOWN" | "UNKNOWN">("");
  const [action, setAction] = useState<AdminAction<unknown> | null>(null);
  const [note, setNote] = useState<Record<string, string>>({});

  const filters: MonitorFilters = {
    owner_id: owner.trim() || undefined,
    paused: paused || undefined,
    health: health || undefined,
  };
  const monitors = useInfiniteQuery({
    queryKey: ["admin-monitors", user?.id, filters.owner_id, filters.paused, filters.health],
    queryFn: ({ signal, pageParam }) =>
      fetchGlobalMonitors(filters, pageParam, signal),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  });
  const rows = monitors.data?.pages.flatMap((p) => p.monitors) ?? [];
  const forbidden =
    monitors.error instanceof ApiError && monitors.error.status === 403;

  const act = (m: AdminMonitorRow, pause: boolean) =>
    setAction({
      title: pause ? "Pause monitor" : "Resume monitor",
      summary: pause
        ? `Pause ${m.name} (owner ${m.owner_id}) globally — the open statistics segment closes; this is a platform action, not the owner's pause.`
        : `Resume ${m.name} — eligible checks reopen at the first future slot; paused time stays honestly missed.`,
      confirmLabel: pause ? "Pause" : "Resume",
      danger: pause,
      run: (reason, idem) =>
        setMonitorPaused(m.id!, pause, m.generation!, reason, idem),
      onDone: (r) => {
        const res = r as { already?: boolean };
        setNote((n) => ({
          ...n,
          [m.id!]: res?.already
            ? "Already in that state — the earlier action stands."
            : pause
              ? "Paused."
              : "Resumed.",
        }));
        monitors.refetch();
      },
    });

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold">Global monitors</h1>
        <p className="mt-1 text-sm text-fg-secondary">
          Platform-wide inventory — targets are redacted to scheme+host;
          path and query secrets never leave the store.
        </p>
      </header>

      <form role="search" aria-label="Filter monitors" className="flex flex-wrap items-end gap-2" onSubmit={(e) => e.preventDefault()}>
        <label className="text-sm">
          <span className="text-fg-secondary">Owner ID</span>
          <input
            value={owner}
            onChange={(e) => setOwner(e.target.value)}
            placeholder="uuid"
            className="mt-1 block w-56 rounded border border-border bg-bg px-2 py-1 font-mono text-xs text-fg"
          />
        </label>
        <label className="text-sm">
          <span className="text-fg-secondary">Paused</span>
          <select value={paused} onChange={(e) => setPaused(e.target.value as typeof paused)} className="mt-1 block rounded border border-border bg-bg px-2 py-1 text-fg">
            <option value="">All</option>
            <option value="true">Paused</option>
            <option value="false">Active</option>
          </select>
        </label>
        <label className="text-sm">
          <span className="text-fg-secondary">Health</span>
          <select value={health} onChange={(e) => setHealth(e.target.value as typeof health)} className="mt-1 block rounded border border-border bg-bg px-2 py-1 text-fg">
            <option value="">All</option>
            <option value="UP">Up</option>
            <option value="DOWN">Down</option>
            <option value="UNKNOWN">Unknown</option>
          </select>
        </label>
      </form>

      {monitors.isPending ? (
        <div role="status" className="text-fg-muted">Loading monitors…</div>
      ) : forbidden ? (
        <div role="alert" className="rounded border border-border bg-container p-3 text-sm text-fg-secondary">
          Your role doesn’t include{" "}
          <code className="font-mono">monitors:global:read</code> — this
          section is denied.
        </div>
      ) : monitors.isError ? (
        <div role="alert" className="rounded border border-down-border bg-down-bg p-3 text-sm text-down-fg">
          Couldn’t load monitors.{" "}
          <button type="button" onClick={() => monitors.refetch()} className="underline">Retry</button>
        </div>
      ) : rows.length === 0 ? (
        <p className="text-sm text-fg-muted">No monitors match these filters.</p>
      ) : (
        <div className="overflow-x-auto rounded border border-border">
          <table className="w-full min-w-[720px] text-left text-sm">
            <thead>
              <tr className="border-b border-border font-mono text-xs text-fg-muted">
                <th scope="col" className="px-3 py-2 font-medium">Name</th>
                <th scope="col" className="px-3 py-2 font-medium">Target</th>
                <th scope="col" className="px-3 py-2 font-medium">Owner</th>
                <th scope="col" className="px-3 py-2 font-medium">Health</th>
                <th scope="col" className="px-3 py-2 font-medium">Gen</th>
                <th scope="col" className="px-3 py-2 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((m) => (
                <tr key={m.id} className="border-b border-border-subtle last:border-0">
                  <td className="px-3 py-2">{m.name}</td>
                  <td className="px-3 py-2 font-mono text-xs text-fg-secondary">{m.target}</td>
                  <td className="px-3 py-2 font-mono text-xs text-fg-muted">{m.owner_id?.slice(0, 8)}…</td>
                  <td className="px-3 py-2">
                    <span className={
                      m.is_paused
                        ? "rounded border border-absent-border bg-absent-bg px-1.5 py-0.5 font-mono text-xs text-absent-fg"
                        : m.health === "DOWN"
                          ? "rounded border border-down-border bg-down-bg px-1.5 py-0.5 font-mono text-xs text-down-fg"
                          : "rounded border border-ok-border bg-ok-bg px-1.5 py-0.5 font-mono text-xs text-ok-fg"
                    }>
                      {m.is_paused ? "paused" : (m.health ?? "unknown").toLowerCase()}
                    </span>
                    {note[m.id!] && (
                      <span className="ml-2 font-mono text-xs text-fg-muted">{note[m.id!]}</span>
                    )}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs">{m.generation}</td>
                  <td className="px-3 py-2">
                    <button
                      type="button"
                      onClick={() => act(m, !m.is_paused)}
                      className="rounded border border-border px-2 py-0.5 text-xs text-fg-secondary hover:text-fg"
                    >
                      {m.is_paused ? "Resume…" : "Pause…"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {monitors.hasNextPage && (
            <div className="border-t border-border p-2 text-center">
              <button
                type="button"
                onClick={() => monitors.fetchNextPage()}
                disabled={monitors.isFetchingNextPage}
                className="rounded border border-border px-3 py-1 text-sm text-fg-secondary hover:text-fg disabled:text-disabled-fg"
              >
                {monitors.isFetchingNextPage ? "Loading…" : "Load more"}
              </button>
            </div>
          )}
        </div>
      )}

      <AdminActionDialog action={action} onClose={() => setAction(null)} />
    </div>
  );
}
