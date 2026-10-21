import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ApiError } from "../../lib/api/client";
import { useSession } from "./session";

export function RegisterPage() {
  const { register } = useSession();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await register({
        email,
        password,
        ...(displayName ? { display_name: displayName } : {}),
      });
      navigate("/login", { replace: true, state: { registered: true } });
    } catch (err) {
      // 409 is intentionally vague server-side (anti-enumeration);
      // field errors arrive under `fields` for the 422 case.
      if (err instanceof ApiError && err.fields) {
        const first = Object.values(err.fields)[0];
        setError(typeof first === "string" ? first : err.message);
      } else {
        setError(err instanceof ApiError ? err.message : "Registration failed");
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="mx-auto mt-16 w-full max-w-sm">
      <h1 className="text-lg font-semibold">Create account</h1>
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
          Display name <span className="text-fg-muted">(optional)</span>
          <input
            type="text"
            autoComplete="nickname"
            maxLength={120}
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            className="rounded border border-border bg-inset px-2 py-1.5 text-fg"
          />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          Password
          <input
            type="password"
            required
            minLength={12}
            autoComplete="new-password"
            aria-describedby="pw-hint"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="rounded border border-border bg-inset px-2 py-1.5 text-fg"
          />
          <span id="pw-hint" className="text-xs text-fg-muted">
            At least 12 characters.
          </span>
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
          {busy ? "Creating…" : "Create account"}
        </button>
      </form>
      <p className="mt-4 text-sm text-fg-muted">
        Have an account?{" "}
        <Link to="/login" className="text-accent-hover underline">
          Sign in
        </Link>
      </p>
    </main>
  );
}
