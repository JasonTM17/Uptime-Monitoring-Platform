import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { ApiError } from "../../../lib/api/client";
import { useSession } from "../../auth/session";
import {
  fetchAdminUsers,
  fetchRoleCatalog,
  type UsersFilters,
} from "../queries";

export function UsersPage() {
  const { user } = useSession();
  const [q, setQ] = useState("");
  const [status, setStatus] = useState<"" | "ACTIVE" | "DISABLED">("");
  const [roleId, setRoleId] = useState("");
  const roles = useQuery({
    queryKey: ["admin-roles", user?.id],
    queryFn: ({ signal }) => fetchRoleCatalog(signal),
    staleTime: 60_000,
  });

  const filters: UsersFilters = {
    q: q.trim() || undefined,
    status: status || undefined,
    role_id: roleId || undefined,
  };
  const users = useInfiniteQuery({
    queryKey: ["admin-users", user?.id, filters.q, filters.status, filters.role_id],
    queryFn: ({ signal, pageParam }) =>
      fetchAdminUsers(filters, pageParam, signal),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  });
  const rows = users.data?.pages.flatMap((p) => p.users) ?? [];
  const forbidden =
    users.error instanceof ApiError && users.error.status === 403;

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold">Users</h1>
        <p className="mt-1 text-sm text-fg-secondary">
          Global user inventory — global scope, separate from your own
          account settings.
        </p>
      </header>

      <form
        role="search"
        aria-label="Filter users"
        className="flex flex-wrap items-end gap-2"
        onSubmit={(e) => e.preventDefault()}
      >
        <label className="text-sm">
          <span className="text-fg-secondary">Email contains</span>
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            className="mt-1 block rounded border border-border bg-bg px-2 py-1 text-fg"
          />
        </label>
        <label className="text-sm">
          <span className="text-fg-secondary">Status</span>
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value as typeof status)}
            className="mt-1 block rounded border border-border bg-bg px-2 py-1 text-fg"
          >
            <option value="">All</option>
            <option value="ACTIVE">Active</option>
            <option value="DISABLED">Disabled</option>
          </select>
        </label>
        <label className="text-sm">
          <span className="text-fg-secondary">Role</span>
          <select
            value={roleId}
            onChange={(e) => setRoleId(e.target.value)}
            className="mt-1 block rounded border border-border bg-bg px-2 py-1 text-fg"
          >
            <option value="">All</option>
            {(roles.data?.roles ?? []).map((r) => (
              <option key={r.id} value={r.id}>
                {r.code}
              </option>
            ))}
          </select>
        </label>
      </form>

      {users.isPending ? (
        <div role="status" className="text-fg-muted">Loading users…</div>
      ) : forbidden ? (
        <div role="alert" className="rounded border border-border bg-container p-3 text-sm text-fg-secondary">
          Your role doesn’t include <code className="font-mono">users:read</code>{" "}
          — this section is denied, not empty.
        </div>
      ) : users.isError ? (
        <div role="alert" className="rounded border border-down-border bg-down-bg p-3 text-sm text-down-fg">
          Couldn’t load users.{" "}
          <button type="button" onClick={() => users.refetch()} className="underline">
            Retry
          </button>
        </div>
      ) : rows.length === 0 ? (
        <p className="text-sm text-fg-muted">No users match these filters.</p>
      ) : (
        <div className="max-w-4xl overflow-x-auto rounded border border-border">
          <table className="w-full min-w-[720px] text-left text-sm">
            <thead>
              <tr className="border-b border-border font-mono text-xs text-fg-muted">
                <th scope="col" className="px-3 py-2 font-medium">Email</th>
                <th scope="col" className="px-3 py-2 font-medium">Status</th>
                <th scope="col" className="px-3 py-2 font-medium">Roles</th>
                <th scope="col" className="px-3 py-2 font-medium">Monitors</th>
                <th scope="col" className="px-3 py-2 font-medium">Sessions</th>
                <th scope="col" className="px-3 py-2 font-medium">Quota</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((u) => (
                <tr key={u.id} className="border-b border-border-subtle last:border-0">
                  <td className="px-3 py-2">
                    <Link
                      to={`/admin/users/${u.id}`}
                      className="text-accent hover:underline"
                    >
                      {u.email}
                    </Link>
                  </td>
                  <td className="px-3 py-2">
                    <span
                      className={
                        u.status === "ACTIVE"
                          ? "rounded border border-ok-border bg-ok-bg px-1.5 py-0.5 font-mono text-xs text-ok-fg"
                          : "rounded border border-down-border bg-down-bg px-1.5 py-0.5 font-mono text-xs text-down-fg"
                      }
                    >
                      {u.status?.toLowerCase()}
                    </span>
                  </td>
                  <td className="px-3 py-2 font-mono text-xs text-fg-secondary">
                    {(u.roles ?? []).join(", ") || "—"}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs">{u.monitors_live}</td>
                  <td className="px-3 py-2 font-mono text-xs">{u.sessions_live}</td>
                  <td className="px-3 py-2 font-mono text-xs">{u.monitor_limit}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {users.hasNextPage && (
            <div className="border-t border-border p-2 text-center">
              <button
                type="button"
                onClick={() => users.fetchNextPage()}
                disabled={users.isFetchingNextPage}
                className="rounded border border-border px-3 py-1 text-sm text-fg-secondary hover:text-fg disabled:text-disabled-fg"
              >
                {users.isFetchingNextPage ? "Loading…" : "Load more"}
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
