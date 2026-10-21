import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { ApiError } from "../../lib/api/client";
import { ReauthDialog } from "../../components/ReauthDialog";
import { useSession } from "../auth/session";
import { fetchSummary } from "../dashboard/queries";
import {
  fetchSessions,
  revokeAllSessions,
  revokeSession,
  type SessionDTO,
} from "./queries";

const t = (s: string | null | undefined) =>
  s ? new Date(s).toLocaleString() : "—";

function Profile() {
  const { user } = useSession();
  const summary = useQuery({
    queryKey: ["dashboard-summary", user?.id],
    queryFn: ({ signal }) => fetchSummary(signal),
    staleTime: 60_000,
  });
  const q = summary.data?.quota;
  return (
    <section aria-label="Profile" className="max-w-2xl">
      <h2 className="mb-2 text-sm font-medium text-fg-secondary">Profile</h2>
      <dl className="grid grid-cols-1 gap-2 rounded border border-border bg-container p-3 sm:grid-cols-2">
        <div>
          <dt className="font-mono text-[10px] uppercase tracking-wide text-fg-muted">Email</dt>
          <dd className="text-sm text-fg">{user?.email}</dd>
        </div>
        <div>
          <dt className="font-mono text-[10px] uppercase tracking-wide text-fg-muted">Display name</dt>
          <dd className="text-sm text-fg">{user?.display_name ?? "—"}</dd>
        </div>
        <div>
          <dt className="font-mono text-[10px] uppercase tracking-wide text-fg-muted">Account status</dt>
          <dd className="text-sm text-fg">{user?.status}</dd>
        </div>
        <div>
          <dt className="font-mono text-[10px] uppercase tracking-wide text-fg-muted">Monitor quota</dt>
          <dd className="text-sm text-fg">
            {q ? `${q.used} / ${q.limit} (${q.profile})` : "—"}
          </dd>
        </div>
      </dl>
      <p className="mt-1 text-xs text-fg-muted">
        Profile fields are managed by the server; there’s no in-app edit.
      </p>
    </section>
  );
}

function SessionRow({
  s,
  onRevoke,
  busy,
}: {
  s: SessionDTO;
  onRevoke: (s: SessionDTO) => void;
  busy: boolean;
}) {
  return (
    <li className="flex flex-wrap items-center gap-3 px-3 py-2">
      <div className="min-w-0">
        <p className="truncate text-sm text-fg">
          {s.device_label}
          {s.current && (
            <span className="ml-2 rounded border border-ok-border bg-ok-bg px-1.5 py-0.5 font-mono text-xs text-ok-fg">
              this session
            </span>
          )}
        </p>
        <p className="font-mono text-xs text-fg-muted">
          signed in {t(s.created_at)} · last seen {t(s.last_seen_at)} ·
          expires {t(s.expires_at)}
        </p>
      </div>
      <button
        type="button"
        onClick={() => onRevoke(s)}
        disabled={busy}
        className="ml-auto rounded border border-border px-2 py-0.5 text-xs text-fg-secondary hover:text-fg disabled:text-disabled-fg"
      >
        Revoke
      </button>
    </li>
  );
}

export function SettingsPage() {
  const { user } = useSession();
  const qc = useQueryClient();
  const [page, setPage] = useState(1);
  const sessions = useQuery({
    queryKey: ["own-sessions", user?.id, page],
    queryFn: ({ signal }) => fetchSessions(page, signal),
  });
  const [actionError, setActionError] = useState<string | null>(null);
  const [confirmAll, setConfirmAll] = useState(false);
  const [reauth, setReauth] = useState<"none" | "all">("none");
  const [revokedCount, setRevokedCount] = useState<number | null>(null);
  const cancelAllRef = useRef<HTMLButtonElement>(null);

  // After the current session dies server-side, forcing an identity
  // re-read surfaces the 401 and the session provider ends the session.
  const forceIdentityRecheck = () =>
    qc.invalidateQueries({ queryKey: ["me"] });

  const revoke = useMutation({
    mutationFn: (s: SessionDTO) => revokeSession(s.id!),
    onSuccess: (_d, s) => {
      setActionError(null);
      qc.invalidateQueries({ queryKey: ["own-sessions"] });
      if (s.current) forceIdentityRecheck();
    },
    onError: (e) =>
      setActionError(
        e instanceof ApiError && e.status === 404
          ? "That session is already gone."
          : "Couldn’t revoke the session.",
      ),
  });

  const revokeAll = useMutation({
    mutationFn: revokeAllSessions,
    onSuccess: (count) => {
      setRevokedCount(count);
      setConfirmAll(false);
      // All sessions including this one are gone; the identity re-read
      // drops the app to login rather than holding privileged data.
      forceIdentityRecheck();
    },
    onError: (e) => {
      setConfirmAll(false);
      if (e instanceof ApiError && e.status === 403 && e.code === "REAUTH_REQUIRED") {
        setReauth("all");
      } else {
        setActionError("Couldn’t revoke sessions — try again.");
      }
    },
  });

  useEffect(() => {
    if (!confirmAll) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setConfirmAll(false);
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [confirmAll]);

  const rows = sessions.data?.sessions ?? [];

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold">Settings</h1>
      </header>

      <Profile />

      <section aria-label="Sessions" className="max-w-2xl">
        <div className="mb-2 flex items-center justify-between">
          <h2 className="text-sm font-medium text-fg-secondary">Sessions</h2>
          <button
            type="button"
            onClick={() => {
              setConfirmAll(true);
              setTimeout(() => cancelAllRef.current?.focus(), 0);
            }}
            className="rounded border border-down-border px-2 py-0.5 text-xs text-down-fg hover:bg-down-bg"
          >
            Sign out everywhere…
          </button>
        </div>
        {actionError && (
          <p role="alert" className="mb-2 text-sm text-down-fg">
            {actionError}
          </p>
        )}
        {revokedCount !== null && (
          <p role="status" className="mb-2 text-sm text-ok-fg">
            {revokedCount} session{revokedCount === 1 ? "" : "s"} revoked.
          </p>
        )}
        {sessions.isPending ? (
          <div role="status" className="text-fg-muted">Loading sessions…</div>
        ) : sessions.isError ? (
          <div role="alert" className="rounded border border-down-border bg-down-bg p-3 text-sm text-down-fg">
            Couldn’t load sessions.{" "}
            <button type="button" onClick={() => sessions.refetch()} className="underline">
              Retry
            </button>
          </div>
        ) : rows.length === 0 ? (
          <p className="text-sm text-fg-muted">No active sessions found.</p>
        ) : (
          <>
            <ul className="divide-y divide-border-subtle rounded border border-border bg-container" aria-label="Sessions">
              {rows.map((s) => (
                <SessionRow
                  key={s.id}
                  s={s}
                  busy={revoke.isPending}
                  onRevoke={(x) => revoke.mutate(x)}
                />
              ))}
            </ul>
            <div className="mt-2 flex items-center gap-2 text-xs text-fg-muted">
              <button
                type="button"
                disabled={page <= 1}
                onClick={() => setPage((p) => p - 1)}
                className="rounded border border-border px-2 py-0.5 disabled:text-disabled-fg"
              >
                Previous
              </button>
              <span>Page {sessions.data?.page ?? page}</span>
              <button
                type="button"
                disabled={rows.length < (sessions.data?.page_size ?? 20)}
                onClick={() => setPage((p) => p + 1)}
                className="rounded border border-border px-2 py-0.5 disabled:text-disabled-fg"
              >
                Next
              </button>
            </div>
          </>
        )}
      </section>

      <section aria-label="Security" className="max-w-2xl">
        <h2 className="mb-2 text-sm font-medium text-fg-secondary">Security</h2>
        <p className="text-xs text-fg-muted">
          Two-factor authentication isn’t offered by this deployment.
        </p>
      </section>

      {confirmAll && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="revoke-all-title"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
        >
          <div className="w-full max-w-sm rounded-lg border border-border bg-container p-4">
            <h2 id="revoke-all-title" className="text-base font-semibold text-fg">
              Sign out everywhere?
            </h2>
            <p className="mt-1 text-sm text-fg-secondary">
              Every session on this account — including this one — will be
              revoked. You’ll need to sign in again on each device.
            </p>
            <div className="mt-4 flex justify-end gap-2">
              <button
                ref={cancelAllRef}
                type="button"
                onClick={() => setConfirmAll(false)}
                className="rounded border border-border px-3 py-1.5 text-sm text-fg-secondary hover:text-fg"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => revokeAll.mutate()}
                disabled={revokeAll.isPending}
                className="rounded bg-down px-3 py-1.5 text-sm font-medium text-white disabled:opacity-50"
              >
                {revokeAll.isPending ? "Revoking…" : "Sign out everywhere"}
              </button>
            </div>
          </div>
        </div>
      )}

      <ReauthDialog
        open={reauth === "all"}
        reason="Signing out everywhere requires a recently confirmed password."
        onCancel={() => setReauth("none")}
        onSuccess={() => {
          setReauth("none");
          // Re-present the explicit confirm — a step-up receipt is not
          // consent, so the destructive call is never replayed silently.
          setConfirmAll(true);
        }}
      />
    </div>
  );
}
