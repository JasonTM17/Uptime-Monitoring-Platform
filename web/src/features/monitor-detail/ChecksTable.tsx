import { useInfiniteQuery } from "@tanstack/react-query";
import { useSession } from "../auth/session";
import { fetchChecks } from "./queries";

const cell = (v: string | number | null | undefined) =>
  v == null ? "—" : String(v);

export function ChecksTable({ monitorId }: { monitorId: string }) {
  const { user } = useSession();
  const checks = useInfiniteQuery({
    queryKey: ["monitor-checks", user?.id, monitorId],
    queryFn: ({ signal, pageParam }) => fetchChecks(monitorId, pageParam, signal),
    initialPageParam: null as string | null,
    getNextPageParam: (last) =>
      last.page.has_more ? (last.page.next_cursor ?? null) : null,
  });
  const rows = checks.data?.pages.flatMap((p) => p.checks) ?? [];

  return (
    <section aria-label="Check history" className="max-w-3xl">
      <h2 className="mb-2 text-sm font-medium text-fg-secondary">
        Check history
      </h2>
      {checks.isPending ? (
        <div role="status" className="text-fg-muted">Loading checks…</div>
      ) : checks.isError ? (
        <div role="alert" className="rounded border border-down-border bg-down-bg p-3 text-sm text-down-fg">
          Couldn’t load check history.{" "}
          <button type="button" onClick={() => checks.refetch()} className="underline">
            Retry
          </button>
        </div>
      ) : rows.length === 0 ? (
        <p className="text-sm text-fg-muted">No check runs recorded yet.</p>
      ) : (
        <div className="overflow-x-auto rounded border border-border">
          <table className="w-full min-w-[640px] text-left font-mono text-xs">
            <thead>
              <tr className="border-b border-border text-fg-muted">
                <th scope="col" className="px-2 py-1 font-medium">Slot (scheduled)</th>
                <th scope="col" className="px-2 py-1 font-medium">Observed (real)</th>
                <th scope="col" className="px-2 py-1 font-medium">Run</th>
                <th scope="col" className="px-2 py-1 font-medium">Outcome</th>
                <th scope="col" className="px-2 py-1 font-medium">HTTP</th>
                <th scope="col" className="px-2 py-1 font-medium">ms</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((c) => (
                <tr key={c.run_id} className="border-b border-border-subtle last:border-0">
                  <td className="px-2 py-1">{cell(c.slot_at)}</td>
                  <td className="px-2 py-1">{cell(c.observed_at)}</td>
                  <td className="px-2 py-1">{cell(c.status)}</td>
                  <td className="px-2 py-1">
                    {c.outcome == null
                      ? "—"
                      : c.success === true
                        ? "SUCCESS"
                        : c.success === false
                          ? "FAIL"
                          : cell(c.outcome)}
                  </td>
                  <td className="px-2 py-1">{cell(c.http_status)}</td>
                  <td className="px-2 py-1">{cell(c.duration_ms)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {checks.hasNextPage && (
            <div className="border-t border-border p-2 text-center">
              <button
                type="button"
                onClick={() => checks.fetchNextPage()}
                disabled={checks.isFetchingNextPage}
                className="rounded border border-border px-3 py-1 text-fg-secondary hover:text-fg disabled:text-disabled-fg"
              >
                {checks.isFetchingNextPage ? "Loading…" : "Load more"}
              </button>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
