import { useState, type FormEvent } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { ApiError } from "../../lib/api/client";
import { useSession } from "./session";

export function LoginPage() {
  const { login, expiredNotice } = useSession();
  const navigate = useNavigate();
  const loc = useLocation();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login({ email, password });
      const back = (loc.state as { from?: string } | null)?.from;
      navigate(back ?? "/", { replace: true });
    } catch (err) {
      // 401/409 messages arrive already generic from the server —
      // render them verbatim, never enumerate why login failed.
      setError(err instanceof ApiError ? err.message : "Sign-in failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="mx-auto mt-16 w-full max-w-sm">
      <h1 className="text-lg font-semibold">Sign in</h1>
      {expiredNotice && (
        <p role="status" className="mt-2 rounded border border-stale-border bg-stale-bg p-2 text-stale-fg">
          Your session expired — sign in again.
        </p>
      )}
      <form onSubmit={submit} className="mt-4 flex flex-col gap-3">
        <label className="flex flex-col gap-1 text-sm">
          Email
          <input
            type="email"
            required
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="rounded border border-border bg-inset px-2 py-1.5 text-fg"
          />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          Password
          <input
            type="password"
            required
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="rounded border border-border bg-inset px-2 py-1.5 text-fg"
          />
        </label>
        {error && (
          <p role="alert" className="text-sm text-down-fg">
            {error}
          </p>
        )}
        <button
          type="submit"
          disabled={busy}
          className="rounded bg-accent px-3 py-1.5 font-medium text-accent-fg disabled:bg-disabled-bg disabled:text-disabled-fg"
        >
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
      <p className="mt-4 text-sm text-fg-muted">
        No account?{" "}
        <Link to="/register" className="text-accent-hover underline">
          Register
        </Link>
      </p>
    </main>
  );
}
