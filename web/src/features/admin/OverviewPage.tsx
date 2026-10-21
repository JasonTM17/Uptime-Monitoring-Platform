import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api/client";
import { useSession } from "../auth/session";

// platform:read overview — counts + engine heartbeat freshness.
// A 503 means a dependency is down, never "healthy zeros".
export function OverviewPage() {
  const { user } = useSession();
  const overview = useQuery({
    queryKey: ["admin-overview", user?.id],
    queryFn: async ({ signal }) => {
      const res = await api("get", "/admin/overview", { signal });
      return res.data as Record<string, unknown> | undefined;
    },
    refetchInterval: 30_000,
    refetchIntervalInBackground: false,
  });
  const d = overview.data;

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold">Admin overview</h1>
        <p className="mt-1 text-sm text-fg-secondary">
          Global scope — every section enforces its own grant; a denied
          section reports that rather than rendering empty.
        </p>
      </header>
      {overview.isPending ? (
        <div role="status" className="text-fg-muted">Loading…</div>
      ) : overview.isError ? (
        <div role="alert" className="rounded border border-down-border bg-down-bg p-3 text-sm text-down-fg">
          Overview unavailable — a dependency may be down. This is not a
          healthy zero.{" "}
          <button type="button" onClick={() => overview.refetch()} className="underline">
            Retry
          </button>
        </div>
      ) : (
        <pre className="max-w-2xl overflow-x-auto rounded border border-border bg-container p-3 font-mono text-xs text-fg">
          {JSON.stringify(d, null, 2)}
        </pre>
      )}
    </div>
  );
}
