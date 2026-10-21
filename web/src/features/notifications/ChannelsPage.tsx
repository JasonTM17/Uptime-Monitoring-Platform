import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { ApiError } from "../../lib/api/client";
import { useSession } from "../auth/session";
import {
  createChannel,
  deleteChannel,
  disableChannel,
  fetchChannels,
  type Channel,
} from "./queries";
import { TestSend } from "./TestSend";

const statusBadge = (s: Channel["status"]) =>
  s === "VERIFIED"
    ? "border-ok-border bg-ok-bg text-ok-fg"
    : s === "DISABLED"
      ? "border-absent-border bg-absent-bg text-absent-fg"
      : "border-stale-border bg-stale-bg text-stale-fg";

const statusLabel = (s: Channel["status"]) =>
  s === "VERIFIED"
    ? "verified"
    : s === "DISABLED"
      ? "disabled"
      : "pending verification";

function allocationMessage(e: ApiError): string | null {
  if (e.status !== 409 || e.code !== "ALLOCATION_LIMIT_REACHED") return null;
  const scope = e.fields?.scope;
  return scope === "pending_channels"
    ? "Pending channel limit reached — wait for verification or delete an unused pending channel."
    : "Channel allocation limit reached for this account.";
}

export function ChannelsPage() {
  const { user } = useSession();
  const qc = useQueryClient();
  const channels = useQuery({
    queryKey: ["channels", user?.id],
    queryFn: ({ signal }) => fetchChannels(signal),
  });
  const [label, setLabel] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<Channel | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);

  const create = useMutation({
    mutationFn: (l: string) => createChannel(l),
    onSuccess: () => {
      setLabel("");
      setFormError(null);
      qc.invalidateQueries({ queryKey: ["channels"] });
    },
    onError: (e) =>
      setFormError(
        e instanceof ApiError
          ? (allocationMessage(e) ??
              (e.status === 422 ? "Check the label and try again." : e.message))
          : "Couldn’t create the channel.",
      ),
  });
  const disable = useMutation({
    mutationFn: (c: Channel) => disableChannel(c.id!, c.version!),
    onSuccess: () => {
      setActionError(null);
      qc.invalidateQueries({ queryKey: ["channels"] });
    },
    onError: (e) =>
      setActionError(
        e instanceof ApiError && e.status === 409
          ? "This channel changed since you loaded the page — refresh and try again."
          : "Couldn’t disable the channel.",
      ),
  });
  const del = useMutation({
    mutationFn: (c: Channel) => deleteChannel(c.id!, c.version!),
    onSuccess: () => {
      setConfirmDelete(null);
      setActionError(null);
      qc.invalidateQueries({ queryKey: ["channels"] });
    },
    onError: (e) =>
      setActionError(
        e instanceof ApiError && e.status === 409
          ? "This channel changed since you loaded the page — refresh and try again."
          : "Couldn’t delete the channel.",
      ),
  });

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold">Notification channels</h1>
        <p className="mt-1 max-w-2xl text-sm text-fg-secondary">
          Channels start as label-only placeholders. An operator verifies the
          destination out-of-band — destination details never travel through
          this app. Verified and enabled channels can be bound to monitors.
        </p>
      </header>

      <form
        aria-label="Create channel"
        className="flex max-w-md items-end gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          const l = label.trim();
          if (!l || create.isPending) return;
          create.mutate(l);
        }}
      >
        <label className="flex-1 text-sm">
          <span className="text-fg-secondary">Channel label</span>
          <input
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            maxLength={120}
            required
            placeholder="e.g. on-call phone"
            className="mt-1 w-full rounded border border-border bg-bg px-2 py-1.5 text-fg"
          />
        </label>
        <button
          type="submit"
          disabled={create.isPending || !label.trim()}
          className="rounded bg-accent px-3 py-1.5 text-sm font-medium text-accent-fg disabled:opacity-50"
        >
          {create.isPending ? "Creating…" : "Create"}
        </button>
      </form>
      {formError && (
        <p role="alert" className="text-sm text-down-fg">
          {formError}
        </p>
      )}
      {actionError && (
        <p role="alert" className="text-sm text-down-fg">
          {actionError}
        </p>
      )}

      {channels.isPending ? (
        <div role="status" className="text-fg-muted">Loading channels…</div>
      ) : channels.isError ? (
        <div role="alert" className="rounded border border-down-border bg-down-bg p-3 text-sm text-down-fg">
          Couldn’t load channels.{" "}
          <button type="button" onClick={() => channels.refetch()} className="underline">
            Retry
          </button>
        </div>
      ) : (channels.data?.length ?? 0) === 0 ? (
        <p className="text-sm text-fg-muted">
          No channels yet. Create a label above; an operator will verify the
          destination before it can receive alerts.
        </p>
      ) : (
        <ul className="max-w-3xl space-y-2" aria-label="Channels">
          {channels.data!.map((c) => (
            <li
              key={c.id}
              className="rounded border border-border bg-container p-3"
            >
              <div className="flex flex-wrap items-center gap-2">
                <strong className="text-fg">{c.label}</strong>
                <span
                  className={`rounded border px-1.5 py-0.5 font-mono text-xs ${statusBadge(c.status)}`}
                >
                  {statusLabel(c.status)}
                </span>
                {!c.enabled && c.status !== "DISABLED" && (
                  <span className="font-mono text-xs text-fg-muted">off</span>
                )}
                {c.destination_mask && (
                  <span className="font-mono text-xs text-fg-muted">
                    {c.destination_mask}
                  </span>
                )}
                <span className="ml-auto flex gap-1">
                  {c.status !== "DISABLED" && (
                    <button
                      type="button"
                      onClick={() => disable.mutate(c)}
                      disabled={disable.isPending}
                      className="rounded border border-border px-2 py-0.5 text-xs text-fg-secondary hover:text-fg"
                    >
                      Disable
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => {
                      setConfirmDelete(c);
                      setTimeout(() => cancelRef.current?.focus(), 0);
                    }}
                    className="rounded border border-down-border px-2 py-0.5 text-xs text-down-fg hover:bg-down-bg"
                  >
                    Delete…
                  </button>
                </span>
              </div>
              <div className="mt-2">
                <TestSend channel={c} />
              </div>
            </li>
          ))}
        </ul>
      )}

      {confirmDelete && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="del-channel-title"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
          onKeyDown={(e) => e.key === "Escape" && setConfirmDelete(null)}
        >
          <div className="w-full max-w-sm rounded-lg border border-border bg-container p-4">
            <h2 id="del-channel-title" className="text-base font-semibold text-fg">
              Delete channel?
            </h2>
            <p className="mt-1 text-sm text-fg-secondary">
              “{confirmDelete.label}” will be removed. History is retained
              server-side; pending channels still count against the allocation
              until it completes.
            </p>
            <div className="mt-4 flex justify-end gap-2">
              <button
                ref={cancelRef}
                type="button"
                onClick={() => setConfirmDelete(null)}
                className="rounded border border-border px-3 py-1.5 text-sm text-fg-secondary hover:text-fg"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => del.mutate(confirmDelete)}
                disabled={del.isPending}
                className="rounded bg-down px-3 py-1.5 text-sm font-medium text-white disabled:opacity-50"
              >
                {del.isPending ? "Deleting…" : "Delete"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
