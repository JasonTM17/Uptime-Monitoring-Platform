import { useInfiniteQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { ApiError } from "../../../lib/api/client";
import { useSession } from "../../auth/session";
import { fetchAuditEvents, type AuditFilters } from "./queries";

const t = (s: string | null | undefined) =>
  s ? new Date(s).toLocaleString() : "—";

// audit:read — append-only history, read-only by design: there is no
// edit, delete, or export affordance on audit records anywhere in the
// UI. Filters are bounded (limit 50/page, cursor-bound to the filter
// set they were minted under server-side).
export function AuditPage() {
  const { user } = useSession();
  const [action, setAction] = useState("");
  const [actor, setActor] = useState("");
  const [subject, setSubject] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");

  const filters: AuditFilters = {
    action: action.trim() || undefined,
    actor: actor.trim() || undefined,
    subject: subject.trim() || undefined,
    from: from || undefined,
    to: to || undefined,
  };
  const audit = useInfiniteQuery({
    queryKey: [
      "admin-audit",
      user?.id,
      filters.action,
      filters.actor,
      filters.subject,
      filters.from,
      filters.to,
    ],
    queryFn: ({ signal, pageParam }) =>
      fetchAuditEvents(filters, pageParam, signal),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  });
  const rows = audit.data?.pages.flatMap((p) => p.events) ?? [];
  const forbidden =
    audit.error instanceof ApiError && audit.error.status === 403;
  const invalid =
    audit.error instanceof ApiError &&
    (audit.error.status === 400 || audit.error.status === 422);

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold">Audit history</h1>
        <p className="mt-1 text-sm text-fg-secondary">
          Append-only record — read-only; there are no edit or export
          controls. Diffs are redacted before they were written.
        </p>
      </header>

      <form
        role="search"
        aria-label="Filter audit events"
        className="flex flex-wrap items-end gap-2"
        onSubmit={(e) => e.preventDefault()}
      >
        <label className="text-sm">
          <span className="text-fg-secondary">Action</span>
          <input
            value={action}
            onChange={(e) => setAction(e.target.value)}
            placeholder="role.update"
            className="mt-1 block w-44 rounded border border-border bg-bg px-2 py-1 font-mono text-xs text-fg"
          />
        </label>
        <label className="text-sm">
          <span className="text-fg-secondary">Actor</span>
          <input
            value={actor}
            onChange={(e) => setActor(e.target.value)}
            placeholder="uuid or kind"
            className="mt-1 block w-40 rounded border border-border bg-bg px-2 py-1 font-mono text-xs text-fg"
          />
        </label>
        <label className="text-sm">
          <span className="text-fg-secondary">Subject</span>
          <input
            value={subject}
            onChange={(e) => setSubject(e.target.value)}
            placeholder="type:id"
            className="mt-1 block w-40 rounded border border-border bg-bg px-2 py-1 font-mono text-xs text-fg"
          />
        </label>
        <label className="text-sm">
          <span className="text-fg-secondary">From</span>
          <input
            type="datetime-local"
            value={from}
            onChange={(e) => setFrom(e.target.value)}
            className="mt-1 block rounded border border-border bg-bg px-2 py-1 font-mono text-xs text-fg"
          />
        </label>
        <label className="text-sm">
          <span className="text-fg-secondary">To</span>
          <input
            type="datetime-local"
            value={to}
            onChange={(e) => setTo(e.target.value)}
            className="mt-1 block rounded border border-border bg-bg px-2 py-1 font-mono text-xs text-fg"
          />
        </label>
      </form>

      {audit.isPending ? (
        <div role="status" className="text-fg-muted">Loading audit…</div>
      ) : forbidden ? (
        <div role="alert" className="rounded border border-border bg-container p-3 text-sm text-fg-secondary">
          Your role doesn’t include{" "}
          <code className="font-mono">audit:read</code> — this section is
          denied.
        </div>
      ) : invalid ? (
        <div role="alert" className="rounded border border-down-border bg-down-bg p-3 text-sm text-down-fg">
          The filters or cursor were rejected — check the values and try
          again. A stale cursor can’t be reused under different filters.
        </div>
      ) : audit.isError ? (
        <div role="alert" className="rounded border border-down-border bg-down-bg p-3 text-sm text-down-fg">
          Couldn’t load the audit history.{" "}
          <button type="button" onClick={() => audit.refetch()} className="underline">
            Retry
          </button>
        </div>
      ) : rows.length === 0 ? (
        <p className="text-sm text-fg-muted">
          No audit events match — that’s an empty result, not a denied or
          broken read.
        </p>
      ) : (
        <div className="overflow-x-auto rounded border border-border">
          <table className="w-full min-w-[720px] text-left text-sm">
            <thead>
              <tr className="border-b border-border font-mono text-xs text-fg-muted">
                <th scope="col" className="px-3 py-2 font-medium">When</th>
                <th scope="col" className="px-3 py-2 font-medium">Actor</th>
                <th scope="col" className="px-3 py-2 font-medium">Action</th>
                <th scope="col" className="px-3 py-2 font-medium">Subject</th>
                <th scope="col" className="px-3 py-2 font-medium">Outcome</th>
                <th scope="col" className="px-3 py-2 font-medium">Detail</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((ev) => (
                <tr key={ev.id} className="border-b border-border-subtle last:border-0">
                  <td className="px-3 py-2 font-mono text-xs text-fg-secondary">{t(ev.created_at)}</td>
                  <td className="px-3 py-2 font-mono text-xs text-fg-secondary">
                    {ev.actor_kind}
                    {ev.actor_id ? ` ${ev.actor_id.slice(0, 8)}…` : ""}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs">{ev.action}</td>
                  <td className="px-3 py-2 font-mono text-xs text-fg-secondary">
                    {ev.subject_type}:{ev.subject_id?.slice(0, 8)}…
                  </td>
                  <td className="px-3 py-2 font-mono text-xs">{ev.outcome}</td>
                  <td className="px-3 py-2">
                    <Link
                      to={`/admin/audit/${ev.id}`}
                      className="rounded border border-border px-2 py-0.5 text-xs text-fg-secondary hover:text-fg"
                    >
                      View
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {audit.hasNextPage && (
            <div className="border-t border-border p-2 text-center">
              <button
                type="button"
                onClick={() => audit.fetchNextPage()}
                disabled={audit.isFetchingNextPage}
                className="rounded border border-border px-3 py-1 text-sm text-fg-secondary hover:text-fg disabled:text-disabled-fg"
              >
                {audit.isFetchingNextPage ? "Loading…" : "Load more"}
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
