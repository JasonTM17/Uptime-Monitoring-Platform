import { useEffect, useRef, useState } from "react";
import { api } from "../lib/api/client";
import { ApiError } from "../lib/api/client";

interface Props {
  open: boolean;
  reason: string;
  onCancel: () => void;
  onSuccess: () => void;
}

// Step-up prompt for sensitive actions. The server stamps recent-auth
// on the session (5-minute TTL); the client only supplies the password.
export function ReauthDialog({ open, reason, onCancel, onSuccess }: Props) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const dialogRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (open) {
      setPassword("");
      setError(null);
      inputRef.current?.focus();
    }
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onCancel();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onCancel]);

  if (!open) return null;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (busy || !password) return;
    setBusy(true);
    setError(null);
    try {
      await api("post", "/auth/reauth", { body: { password } });
      onSuccess();
    } catch (err) {
      setError(
        err instanceof ApiError && err.status === 429
          ? "Too many attempts — wait a moment and try again."
          : "Password verification failed.",
      );
      setPassword("");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="reauth-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      ref={dialogRef}
    >
      <form
        onSubmit={submit}
        className="w-full max-w-sm rounded-lg border border-border bg-container p-4"
      >
        <h2 id="reauth-title" className="text-base font-semibold text-fg">
          Confirm it’s you
        </h2>
        <p className="mt-1 text-sm text-fg-secondary">{reason}</p>
        <label className="mt-3 block text-sm">
          <span className="text-fg-secondary">Password</span>
          <input
            ref={inputRef}
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
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
            onClick={onCancel}
            className="rounded border border-border px-3 py-1.5 text-sm text-fg-secondary hover:text-fg"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={busy || !password}
            className="rounded bg-accent px-3 py-1.5 text-sm font-medium text-accent-fg disabled:opacity-50"
          >
            {busy ? "Verifying…" : "Continue"}
          </button>
        </div>
      </form>
    </div>
  );
}
