import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ApiError } from "../../../lib/api/client";
import { useSession } from "../../auth/session";
import { AdminActionDialog, type AdminAction } from "../AdminActionDialog";
import {
  assignUserRoles,
  fetchAdminUser,
  fetchRoleCatalog,
  restoreUser,
  revokeUserSessions,
  setUserQuota,
  suspendUser,
} from "../queries";

const t = (s: string | null | undefined) =>
  s ? new Date(s).toLocaleString() : "—";

export function UserDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { user: actor } = useSession();
  const qc = useQueryClient();
  const detail = useQuery({
    queryKey: ["admin-user", actor?.id, id],
    queryFn: ({ signal }) => fetchAdminUser(id!, signal),
    enabled: !!id,
  });
  const roles = useQuery({
    queryKey: ["admin-roles", actor?.id],
    queryFn: ({ signal }) => fetchRoleCatalog(signal),
    staleTime: 60_000,
  });
  const [action, setAction] = useState<AdminAction<unknown> | null>(null);
  const [quotaDraft, setQuotaDraft] = useState<string | null>(null);
  const [roleDraft, setRoleDraft] = useState<string[] | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const u = detail.data;
  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["admin-user", actor?.id, id] });
    qc.invalidateQueries({ queryKey: ["admin-users"] });
  };
  const forbidden =
    detail.error instanceof ApiError && detail.error.status === 403;

  const catalog = roles.data?.roles ?? [];
  const userRoleIds = new Set(
    catalog.filter((r) => (u?.roles ?? []).includes(r.code!)).map((r) => r.id!),
  );

  return (
    <div className="max-w-3xl space-y-4">
      <Link to="/admin/users" className="text-sm text-accent hover:underline">
        ← Users
      </Link>
      {detail.isPending ? (
        <div role="status" className="text-fg-muted">Loading user…</div>
      ) : forbidden ? (
        <div role="alert" className="rounded border border-border bg-container p-3 text-sm text-fg-secondary">
          Your role doesn’t include <code className="font-mono">users:read</code>{" "}
          — this section is denied.
        </div>
      ) : detail.isError || !u ? (
        <div role="alert" className="rounded border border-down-border bg-down-bg p-3 text-sm text-down-fg">
          {detail.error instanceof ApiError && detail.error.status === 404
            ? "User not found."
            : "Couldn't load the user."}{" "}
          <button type="button" onClick={() => detail.refetch()} className="underline">
            Retry
          </button>
        </div>
      ) : (
        <>
          <header className="flex flex-wrap items-center gap-3">
            <h1 className="text-xl font-semibold">{u.email}</h1>
            <span
              className={
                u.status === "ACTIVE"
                  ? "rounded border border-ok-border bg-ok-bg px-1.5 py-0.5 font-mono text-xs text-ok-fg"
                  : "rounded border border-down-border bg-down-bg px-1.5 py-0.5 font-mono text-xs text-down-fg"
              }
            >
              {u.status?.toLowerCase()}
            </span>
            <span className="font-mono text-xs text-fg-muted">
              v{u.version} · epoch {u.security_version}
            </span>
          </header>
          {notice && (
            <p role="status" className="text-sm text-ok-fg">
              {notice}
            </p>
          )}

          <dl className="grid grid-cols-2 gap-2 rounded border border-border bg-container p-3 sm:grid-cols-4">
            {(
              [
                ["Display name", u.display_name || "—"],
                ["Monitors", String(u.monitors_live)],
                ["Live sessions", String(u.sessions_live)],
                ["Monitor cap", String(u.monitor_limit)],
                ["Created", t(u.created_at)],
                ["Disabled", t(u.disabled_at)],
              ] as const
            ).map(([k, v]) => (
              <div key={k}>
                <dt className="font-mono text-[10px] uppercase tracking-wide text-fg-muted">{k}</dt>
                <dd className="text-sm text-fg">{v}</dd>
              </div>
            ))}
          </dl>

          <section aria-label="Actions" className="space-y-2">
            <h2 className="text-sm font-medium text-fg-secondary">Actions</h2>
            <div className="flex flex-wrap gap-2">
              {u.status === "ACTIVE" ? (
                <button
                  type="button"
                  onClick={() =>
                    setAction({
                      title: "Suspend account",
                      summary: `Suspend ${u.email}: sessions revoked, monitors fenced, epoch bumped. In-flight privileged writes lose their grant.`,
                      confirmLabel: "Suspend",
                      danger: true,
                      run: (reason, idem) =>
                        suspendUser(id!, u.version!, reason, idem),
                      onDone: (r) => {
                        const res = r as { already?: boolean };
                        setNotice(
                          res?.already
                            ? "Already disabled — the earlier suspend stands."
                            : "Account suspended.",
                        );
                        refresh();
                      },
                    })
                  }
                  className="rounded border border-down-border px-3 py-1 text-sm text-down-fg hover:bg-down-bg"
                >
                  Suspend…
                </button>
              ) : (
                <button
                  type="button"
                  onClick={() =>
                    setAction({
                      title: "Restore account",
                      summary: `Restore ${u.email}: account reactivates — revoked sessions stay revoked and removed grants are not re-issued.`,
                      confirmLabel: "Restore",
                      run: (reason, idem) =>
                        restoreUser(id!, u.version!, reason, idem),
                      onDone: () => {
                        setNotice(
                          "Account restored. Sessions and removed grants were not re-issued.",
                        );
                        refresh();
                      },
                    })
                  }
                  className="rounded border border-ok-border px-3 py-1 text-sm text-ok-fg hover:bg-ok-bg"
                >
                  Restore…
                </button>
              )}
              <button
                type="button"
                onClick={() =>
                  setAction({
                    title: "Revoke all sessions",
                    summary: `Revoke every live session for ${u.email} — they stay revoked; the user must sign in again.`,
                    confirmLabel: "Revoke sessions",
                    danger: true,
                    run: (reason, idem) =>
                      revokeUserSessions(id!, u.version!, reason, idem),
                    onDone: (r) => {
                      const res = r as { sessions_revoked?: number };
                      setNotice(
                        `${res?.sessions_revoked ?? 0} session(s) revoked.`,
                      );
                      refresh();
                    },
                  })
                }
                className="rounded border border-border px-3 py-1 text-sm text-fg-secondary hover:text-fg"
              >
                Revoke sessions…
              </button>
            </div>
          </section>

          <section aria-label="Quota" className="space-y-2">
            <h2 className="text-sm font-medium text-fg-secondary">Monitor quota</h2>
            <form
              className="flex items-end gap-2"
              onSubmit={(e) => {
                e.preventDefault();
                const n = parseInt(quotaDraft ?? "", 10);
                if (Number.isNaN(n) || n < 0) return;
                setAction({
                  title: "Set monitor cap",
                  summary: `Set ${u.email}'s live monitor cap to ${n} — monitors already created are not deleted.`,
                  confirmLabel: "Set cap",
                  run: (reason, idem) =>
                    setUserQuota(id!, n, u.version!, reason, idem),
                  onDone: () => {
                    setNotice(`Monitor cap set to ${n}.`);
                    setQuotaDraft(null);
                    refresh();
                  },
                });
              }}
            >
              <label className="text-sm">
                <span className="text-fg-secondary">New cap</span>
                <input
                  type="number"
                  min={0}
                  value={quotaDraft ?? ""}
                  placeholder={String(u.monitor_limit)}
                  onChange={(e) => setQuotaDraft(e.target.value)}
                  className="mt-1 block w-28 rounded border border-border bg-bg px-2 py-1 text-fg"
                />
              </label>
              <button
                type="submit"
                disabled={quotaDraft == null || quotaDraft === ""}
                className="rounded border border-border px-3 py-1 text-sm text-fg-secondary hover:text-fg disabled:text-disabled-fg"
              >
                Update…
              </button>
            </form>
          </section>

          <section aria-label="Role assignment" className="space-y-2">
            <h2 className="text-sm font-medium text-fg-secondary">
              Roles <span className="font-mono text-xs text-fg-muted">(atomic replace)</span>
            </h2>
            <div className="flex flex-wrap gap-2">
              {catalog.map((r) => {
                const checked = roleDraft
                  ? roleDraft.includes(r.id!)
                  : userRoleIds.has(r.id!);
                return (
                  <label
                    key={r.id}
                    className={`flex cursor-pointer items-center gap-1 rounded border px-2 py-1 font-mono text-xs ${
                      checked
                        ? "border-accent bg-accent-subtle text-fg"
                        : "border-border text-fg-secondary"
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => {
                        const base = roleDraft ?? [...userRoleIds];
                        setRoleDraft(
                          checked
                            ? base.filter((x) => x !== r.id)
                            : [...base, r.id!],
                        );
                      }}
                      className="accent-accent"
                    />
                    {r.code}
                  </label>
                );
              })}
            </div>
            {roleDraft && (
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() =>
                    setAction({
                      title: "Replace role set",
                      summary: `Replace ${u.email}'s roles with the selected set — atomic; the subject's security epoch advances on commit.`,
                      confirmLabel: "Replace roles",
                      danger: true,
                      run: (reason, idem) =>
                        assignUserRoles(id!, roleDraft, u.version!, reason, idem),
                      onDone: () => {
                        setNotice("Role set replaced — epoch advanced.");
                        setRoleDraft(null);
                        refresh();
                      },
                    })
                  }
                  className="rounded bg-accent px-3 py-1 text-sm font-medium text-accent-fg"
                >
                  Apply roles…
                </button>
                <button
                  type="button"
                  onClick={() => setRoleDraft(null)}
                  className="rounded border border-border px-3 py-1 text-sm text-fg-secondary"
                >
                  Discard
                </button>
              </div>
            )}
          </section>
        </>
      )}

      <AdminActionDialog
        action={action}
        onClose={() => setAction(null)}
      />
    </div>
  );
}
