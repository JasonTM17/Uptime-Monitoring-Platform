// Shared engine-liveness rendering. freshness is a tri-state
// (fresh | stale | absent) — "absent" means the backend has no
// heartbeat row at all and is never rendered as healthy.
export function FreshnessBadge({
  value,
}: {
  value: string | null | undefined;
}) {
  const cls =
    value === "fresh"
      ? "border-ok-border bg-ok-bg text-ok-fg"
      : value === "stale"
        ? "border-stale-border bg-stale-bg text-stale-fg"
        : "border-absent-border bg-absent-bg text-absent-fg";
  return (
    <span className={`rounded border px-1.5 py-0.5 font-mono text-xs ${cls}`}>
      {value ?? "absent"}
    </span>
  );
}
