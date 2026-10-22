import { useRef, useState, type FormEvent } from "react";
import { ApiError } from "../../lib/api/client";

export interface MonitorFormValues {
  name: string;
  target_url: string;
  interval_seconds: number;
  timeout_seconds: number;
  expected_status: number | null;
}

// Client constraints mirror the contract for UX only — SSRF/URL
// policy is decided at actual dial time on the server, never here.
const LIMITS = {
  name: { min: 1, max: 120 },
  interval: { min: 60, max: 86400 },
  timeout: { min: 1, max: 10 },
  status: { min: 200, max: 599 },
} as const;

export function validate(v: MonitorFormValues): Record<string, string> {
  const errs: Record<string, string> = {};
  if (v.name.trim().length < LIMITS.name.min || v.name.length > LIMITS.name.max)
    errs.name = `Name must be 1–${LIMITS.name.max} characters`;
  try {
    const u = new URL(v.target_url);
    if (u.protocol !== "http:" && u.protocol !== "https:")
      errs.target_url = "Only http/https URLs are accepted";
    else if (u.username || u.password)
      errs.target_url = "URLs with embedded credentials are not accepted";
  } catch {
    errs.target_url = "Enter a valid URL";
  }
  if (
    !Number.isInteger(v.interval_seconds) ||
    v.interval_seconds < LIMITS.interval.min ||
    v.interval_seconds > LIMITS.interval.max
  )
    errs.interval_seconds = `Interval must be ${LIMITS.interval.min}–${LIMITS.interval.max}s`;
  if (
    !Number.isInteger(v.timeout_seconds) ||
    v.timeout_seconds < LIMITS.timeout.min ||
    v.timeout_seconds > LIMITS.timeout.max
  )
    errs.timeout_seconds = `Timeout must be ${LIMITS.timeout.min}–${LIMITS.timeout.max}s`;
  else if (v.timeout_seconds > v.interval_seconds)
    errs.timeout_seconds = "Timeout can’t exceed the check interval";
  if (
    v.expected_status !== null &&
    (!Number.isInteger(v.expected_status) ||
      v.expected_status < LIMITS.status.min ||
      v.expected_status > LIMITS.status.max)
  )
    errs.expected_status = `Status must be ${LIMITS.status.min}–${LIMITS.status.max}`;
  return errs;
}

export function MonitorForm({
  initial,
  onSubmit,
  submitLabel,
  generationConflict,
  onDismissConflict,
}: {
  initial: MonitorFormValues;
  onSubmit: (v: MonitorFormValues) => Promise<void>;
  submitLabel: string;
  generationConflict: boolean;
  onDismissConflict: () => void;
}) {
  const [v, setV] = useState(initial);
  const [errs, setErrs] = useState<Record<string, string>>({});
  const [topError, setTopError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const refs = {
    name: useRef<HTMLInputElement>(null),
    target_url: useRef<HTMLInputElement>(null),
    interval_seconds: useRef<HTMLInputElement>(null),
    timeout_seconds: useRef<HTMLInputElement>(null),
    expected_status: useRef<HTMLInputElement>(null),
  };

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (busy) return;
    const fieldErrs = validate(v);
    setErrs(fieldErrs);
    if (Object.keys(fieldErrs).length > 0) {
      const first = Object.keys(fieldErrs)[0] as keyof typeof refs;
      refs[first]?.current?.focus();
      return;
    }
    setBusy(true);
    setTopError(null);
    try {
      await onSubmit(v);
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 422 && err.fields) {
          setErrs(
            Object.fromEntries(
              Object.entries(err.fields).map(([k, val]) => [k, String(val)]),
            ),
          );
          const first = Object.keys(err.fields)[0] as keyof typeof refs;
          refs[first]?.current?.focus();
        } else if (err.status === 409 && err.code !== "GENERATION_CONFLICT") {
          // Quota/allocation conflicts: surface the safe scope label.
          const scope = err.fields?.scope;
          setTopError(
            scope ? `${err.message} (${String(scope)})` : err.message,
          );
        } else if (err.status === 429) {
          setTopError("Rate limited — wait a moment and try again.");
        } else if (err.status !== 409) {
          // 409 GENERATION_CONFLICT is handled by the caller's banner.
          setTopError(err.message);
        }
      } else {
        setTopError("Request failed — check your connection.");
      }
    } finally {
      setBusy(false);
    }
  }

  const num = (s: string) => (s === "" ? NaN : Number(s));

  return (
    <form onSubmit={submit} className="flex max-w-lg flex-col gap-3" noValidate>
      {generationConflict && (
        <div
          role="alert"
          className="rounded border border-stale-border bg-stale-bg p-2 text-sm text-stale-fg"
        >
          This monitor changed elsewhere — review the latest values before
          saving again.{" "}
          <button type="button" onClick={onDismissConflict} className="underline">
            Reload latest
          </button>
        </div>
      )}
      {topError && (
        <p role="alert" className="text-sm text-down-fg">
          {topError}
        </p>
      )}

      <label className="flex flex-col gap-1 text-sm">
        Name
        <input
          ref={refs.name}
          value={v.name}
          onChange={(e) => setV({ ...v, name: e.target.value })}
          maxLength={LIMITS.name.max}
          required
          aria-invalid={!!errs.name}
          aria-describedby={errs.name ? "err-name" : undefined}
          className="w-full min-w-0 rounded border border-border bg-inset px-2 py-1.5 text-fg"
        />
        {errs.name && (
          <span id="err-name" role="alert" className="text-xs text-down-fg">
            {errs.name}
          </span>
        )}
      </label>

      <label className="flex flex-col gap-1 text-sm">
        Target URL
        <input
          ref={refs.target_url}
          type="url"
          inputMode="url"
          value={v.target_url}
          onChange={(e) => setV({ ...v, target_url: e.target.value })}
          required
          aria-invalid={!!errs.target_url}
          aria-describedby={errs.target_url ? "err-url" : "hint-url"}
          className="w-full min-w-0 rounded border border-border bg-inset px-2 py-1.5 font-mono text-fg"
        />
        {errs.target_url ? (
          <span id="err-url" role="alert" className="text-xs text-down-fg">
            {errs.target_url}
          </span>
        ) : (
          <span id="hint-url" className="text-xs text-fg-muted">
            Public http/https. Reachability policy is verified at check time.
          </span>
        )}
      </label>

      <div className="grid grid-cols-3 gap-3">
        <label className="flex min-w-0 flex-col gap-1 overflow-hidden text-sm">
          Interval (s)
          <input
            ref={refs.interval_seconds}
            type="number"
            inputMode="numeric"
            min={LIMITS.interval.min}
            max={LIMITS.interval.max}
            value={Number.isNaN(v.interval_seconds) ? "" : v.interval_seconds}
            onChange={(e) =>
              setV({ ...v, interval_seconds: num(e.target.value) })
            }
            required
            aria-invalid={!!errs.interval_seconds}
            className="w-full min-w-0 rounded border border-border bg-inset px-2 py-1.5 font-mono text-fg"
          />
          {errs.interval_seconds && (
            <span role="alert" className="text-xs text-down-fg">
              {errs.interval_seconds}
            </span>
          )}
        </label>
        <label className="flex min-w-0 flex-col gap-1 overflow-hidden text-sm">
          Timeout (s)
          <input
            ref={refs.timeout_seconds}
            type="number"
            inputMode="numeric"
            min={LIMITS.timeout.min}
            max={LIMITS.timeout.max}
            value={Number.isNaN(v.timeout_seconds) ? "" : v.timeout_seconds}
            onChange={(e) =>
              setV({ ...v, timeout_seconds: num(e.target.value) })
            }
            required
            aria-invalid={!!errs.timeout_seconds}
            className="w-full min-w-0 rounded border border-border bg-inset px-2 py-1.5 font-mono text-fg"
          />
          {errs.timeout_seconds && (
            <span role="alert" className="text-xs text-down-fg">
              {errs.timeout_seconds}
            </span>
          )}
        </label>
        <label className="flex min-w-0 flex-col gap-1 overflow-hidden text-sm">
          Expected status
          <input
            ref={refs.expected_status}
            type="number"
            inputMode="numeric"
            min={LIMITS.status.min}
            max={LIMITS.status.max}
            value={v.expected_status ?? ""}
            onChange={(e) =>
              setV({
                ...v,
                expected_status:
                  e.target.value === "" ? null : num(e.target.value),
              })
            }
            aria-invalid={!!errs.expected_status}
            aria-describedby="hint-status"
            className="w-full min-w-0 rounded border border-border bg-inset px-2 py-1.5 font-mono text-fg"
          />
          {errs.expected_status ? (
            <span role="alert" className="text-xs text-down-fg">
              {errs.expected_status}
            </span>
          ) : (
            <span id="hint-status" className="text-xs text-fg-muted">
              optional
            </span>
          )}
        </label>
      </div>

      <button
        type="submit"
        disabled={busy}
        className="self-start rounded bg-accent px-3 py-1.5 font-medium text-accent-fg disabled:bg-disabled-bg disabled:text-disabled-fg"
      >
        {busy ? "Saving…" : submitLabel}
      </button>
    </form>
  );
}
