import { useInfiniteQuery } from "@tanstack/react-query";
import { useState } from "react";
import { ApiError } from "../../../lib/api/client";
import { useSession } from "../../auth/session";
import { AdminActionDialog, type AdminAction } from "../AdminActionDialog";
import {
  fetchOutbox,
  retryDelivery,
  suppressDelivery,
  type AdminOutboxRow,
  type OutboxFilters,
} from "./queries";

const t = (s: string | null | undefined) =>
  s ? new Date(s).toLocaleString() : "—";

// deliveries:read — the notification outbox. Retry re-arms ONE dead
// stream head (a 202 receipt = re-queued, not delivered); suppress
// terminalizes the head plus every live descendant. Both actions are
// version-fenced and reasoned through the privileged dialog; nothing
// mutates optimistically.
export function OutboxPage() {
  const { user } = useSession();
  const [state, setState] = useState<"" | OutboxFilters["state"]>("");
  const [action, setAction] = useState<AdminAction<unknown> | null>(null);
  const [note, setNote] = useState<Record<string, string>>({});

  const filters: OutboxFilters = { state: state || undefined };
  const outbox = useInfiniteQuery({
    queryKey: ["admin-outbox", user?.id, filters.state],
    queryFn: ({ signal, pageParam }) => fetchOutbox(filters, pageParam, signal),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  });
  const rows = outbox.data?.pages.flatMap((p) => p.deliveries) ?? [];
  const forbidden =
    outbox.error instanceof ApiError && outbox.error.status === 403;

  const act = (d: AdminOutboxRow, kind: "retry" | "suppress") =>
    setAction({
      title: kind === "retry" ? "Retry delivery" : "Suppress delivery stream",
      summary:
        kind === "retry"
          ? `Re-arm the DEAD stream head ${d.id} (event ${d.event_kind}). A 202 receipt means re-queued PENDING — not sent or delivered. Retry only works on a dead head; a live predecessor or non-dead row conflicts with 409.`
          : `Terminalize stream head ${d.id} and every live descendant under it (${d.event_kind}). Suppressed deliveries never send — this is how a dead predecessor that can't recover is cut loose.`,
      confirmLabel: kind === "retry" ? "Retry" : "Suppress",
      danger: kind === "suppress",
      run: (reason, idem) =>
        kind === "retry"
          ? retryDelivery(d.id!, d.version!, reason, idem)
          : suppressDelivery(d.id!, d.version!, reason, idem),
      onDone: (r) => {
        const res = r as { state?: string };
        setNote((n) => ({
          ...n,
          [d.id!]:
            kind === "retry"
              ? `Receipt: re-queued ${res?.state ?? "PENDING"} — not delivered.`
              : `Suppressed — ${res?.state ?? "SUPPRESSED"}.`,
        }));
        outbox.refetch();
      },
    });

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold">Delivery outbox</h1>
        <p className="mt-1 text-sm text-fg-secondary">
          A receipt means queued — never delivered. Dead heads can retry;
          a dead predecessor blocks its successors’ recovery until the
          stream is suppressed.
        </p>
      </header>

      <form role="search" aria-label="Filter outbox" className="flex items-end gap-2" onSubmit={(e) => e.preventDefault()}>
        <label className="text-sm">
          <span className="text-fg-secondary">State</span>
          <select value={state} onChange={(e) => setState(e.target.value as typeof state)} className="mt-1 block rounded border border-border bg-bg px-2 py-1 text-fg">
            <option value="">All</option>
            {(["PENDING", "LEASED", "SENT", "DEAD", "SUPPRESSED"] as const).map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </label>
      </form>

      {outbox.isPending ? (
        <div role="status" className="text-fg-muted">Loading outbox…</div>
      ) : forbidden ? (
        <div role="alert" className="rounded border border-border bg-container p-3 text-sm text-fg-secondary">
          Your role doesn’t include{" "}
          <code className="font-mono">deliveries:read</code> — this section
          is denied.
        </div>
      ) : outbox.isError ? (
        <div role="alert" className="rounded border border-down-border bg-down-bg p-3 text-sm text-down-fg">
          Couldn’t load the outbox.{" "}
          <button type="button" onClick={() => outbox.refetch()} className="underline">Retry</button>
        </div>
      ) : rows.length === 0 ? (
        <p className="text-sm text-fg-muted">
          No deliveries in this state — the outbox is quiet.
        </p>
      ) : (
        <div className="overflow-x-auto rounded border border-border">
          <table className="w-full min-w-[720px] text-left text-sm">
            <thead>
              <tr className="border-b border-border font-mono text-xs text-fg-muted">
                <th scope="col" className="px-3 py-2 font-medium">Delivery</th>
                <th scope="col" className="px-3 py-2 font-medium">Event</th>
                <th scope="col" className="px-3 py-2 font-medium">State</th>
                <th scope="col" className="px-3 py-2 font-medium">Attempts</th>
                <th scope="col" className="px-3 py-2 font-medium">Next attempt</th>
                <th scope="col" className="px-3 py-2 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((d) => (
                <tr key={d.id} className="border-b border-border-subtle last:border-0">
                  <td className="px-3 py-2 font-mono text-xs text-fg-muted">
                    {d.id?.slice(0, 8)}…
                    {d.last_error_code && (
                      <div className="mt-0.5 text-down-fg">{d.last_error_code}</div>
                    )}
                    {note[d.id!] && (
                      <div className="mt-0.5 text-fg-secondary">{note[d.id!]}</div>
                    )}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs">{d.event_kind}</td>
                  <td className="px-3 py-2">
                    <span className={`rounded border px-1.5 py-0.5 font-mono text-xs ${
                      d.state === "DEAD" || d.state === "SUPPRESSED"
                        ? "border-down-border bg-down-bg text-down-fg"
                        : d.state === "SENT"
                          ? "border-ok-border bg-ok-bg text-ok-fg"
                          : "border-absent-border bg-absent-bg text-absent-fg"
                    }`}>{d.state}</span>
                  </td>
                  <td className="px-3 py-2 font-mono text-xs">{d.attempts}</td>
                  <td className="px-3 py-2 font-mono text-xs text-fg-secondary">{t(d.next_attempt_at)}</td>
                  <td className="px-3 py-2">
                    {d.state === "DEAD" && (
                      <span className="flex gap-1.5">
                        <button type="button" onClick={() => act(d, "retry")} className="rounded border border-border px-2 py-0.5 text-xs text-fg-secondary hover:text-fg">
                          Retry…
                        </button>
                        <button type="button" onClick={() => act(d, "suppress")} className="rounded border border-down-border px-2 py-0.5 text-xs text-down-fg hover:bg-down-bg">
                          Suppress…
                        </button>
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {outbox.hasNextPage && (
            <div className="border-t border-border p-2 text-center">
              <button
                type="button"
                onClick={() => outbox.fetchNextPage()}
                disabled={outbox.isFetchingNextPage}
                className="rounded border border-border px-3 py-1 text-sm text-fg-secondary hover:text-fg disabled:text-disabled-fg"
              >
                {outbox.isFetchingNextPage ? "Loading…" : "Load more"}
              </button>
            </div>
          )}
        </div>
      )}

      <AdminActionDialog action={action} onClose={() => setAction(null)} />
    </div>
  );
}
