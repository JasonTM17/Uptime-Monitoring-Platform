import { useEffect, useRef, useState } from "react";
import { ApiError } from "../../lib/api/client";
import { ReauthDialog } from "../../components/ReauthDialog";

export interface AdminAction<T> {
  title: string;
  // One sentence describing target + effect, rendered before confirm.
  summary: string;
  confirmLabel: string;
  danger?: boolean;
  run: (reason: string, idemKey: string) => Promise<T>;
  onDone: (result: T) => void;
}

interface Props {
  action: AdminAction<unknown> | null;
  onClose: () => void;
}

// Generic privileged-mutation dialog: reason (required 1–500) + confirm.
// A fresh Idempotency-Key is minted once per opened intent and reused
// across retries so the server replays the same logical request — it
// is never re-minted mid-flow. REAUTH_REQUIRED opens the step-up and
// re-presents this confirm; nothing replays silently.
export function AdminActionDialog({ action, onClose }: Props) {
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [reauth, setReauth] = useState(false);
  const idemRef = useRef("");
  const reasonRef = useRef("");

  useEffect(() => {
    if (action) {
      setReason("");
      setError(null);
      setBusy(false);
      setReauth(false);
      idemRef.current = crypto.randomUUID();
      reasonRef.current = "";
    }
  }, [action]);

  useEffect(() => {
    if (!action) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [action, onClose]);

  if (!action) return null;

  const submit = async () => {
    const r = reason.trim();
    if (busy || !r) return;
    setBusy(true);
    setError(null);
    reasonRef.current = r;
    try {
      const result = await action.run(r, idemRef.current);
      action.onDone(result);
      onClose();
    } catch (e) {
      if (
        e instanceof ApiError &&
        e.status === 403 &&
        e.code === "REAUTH_REQUIRED"
      ) {
        setReauth(true);
      } else if (e instanceof ApiError && e.code === "LAST_SUPERADMIN") {
        setError(
          "The last active superadmin can’t be removed — promote another superadmin first.",
        );
      } else if (e instanceof ApiError && e.status === 409) {
        setError(
          "This record changed since you loaded it — refresh and review before retrying.",
        );
      } else if (e instanceof ApiError && e.status === 403) {
        setError("Your role doesn’t grant this capability.");
      } else if (e instanceof ApiError && e.status === 422) {
        const missing = e.fields?.missing_permissions;
        setError(
          typeof missing === "string"
            ? `Missing prerequisite grant(s): ${missing}.`
            : "Validation failed — check the fields and try again.",
        );
      } else {
        setError("The action failed — nothing was applied.");
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="admin-action-title"
        className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      >
        <div className="w-full max-w-md rounded-lg border border-border bg-container p-4">
          <h2 id="admin-action-title" className="text-base font-semibold text-fg">
            {action.title}
          </h2>
          <p className="mt-1 text-sm text-fg-secondary">{action.summary}</p>
          <label className="mt-3 block text-sm">
            <span className="text-fg-secondary">
              Reason <span className="text-fg-muted">(recorded in audit)</span>
            </span>
            <textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              maxLength={500}
              required
              rows={2}
              className="mt-1 w-full rounded border border-border bg-bg px-2 py-1.5 text-fg"
            />
          </label>
          {error && (
            <p role="alert" className="mt-2 text-sm text-down-fg">
              {error}
            </p>
          )}
          <div className="mt-4 flex justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded border border-border px-3 py-1.5 text-sm text-fg-secondary hover:text-fg"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={submit}
              disabled={busy || !reason.trim()}
              className={`rounded px-3 py-1.5 text-sm font-medium text-white disabled:opacity-50 ${
                action.danger ? "bg-down" : "bg-accent"
              }`}
            >
              {busy ? "Working…" : action.confirmLabel}
            </button>
          </div>
        </div>
      </div>
      <ReauthDialog
        open={reauth}
        reason="This administrative action requires a recently confirmed password."
        onCancel={() => setReauth(false)}
        onSuccess={() => setReauth(false)}
      />
    </>
  );
}
