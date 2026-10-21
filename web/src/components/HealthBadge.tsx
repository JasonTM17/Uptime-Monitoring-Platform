import type { components } from "../lib/api/schema";

type Health = components["schemas"]["Monitor"]["health"];

// Badge semantics — a paused monitor is paused (not healthy/down);
// stale evidence keeps the real health but marks data age; absent
// evidence never claims UP.
export function HealthBadge({
  health,
  isPaused,
  freshness,
}: {
  health: Health;
  isPaused: boolean;
  freshness: string | null;
}) {
  if (isPaused) {
    return (
      <span className="rounded border border-paused-border bg-paused-bg px-1.5 py-0.5 font-mono text-xs text-paused-fg">
        PAUSED
      </span>
    );
  }
  const stale = freshness === "stale";
  const cls =
    health === "UP"
      ? "border-up-border bg-up-bg text-up-fg"
      : health === "DOWN"
        ? "border-down-border bg-down-bg text-down-fg"
        : "border-absent-border bg-absent-bg text-absent-fg";
  return (
    <span className="inline-flex items-center gap-1">
      <span className={`rounded border px-1.5 py-0.5 font-mono text-xs ${cls}`}>
        {health}
      </span>
      {stale && (
        <span className="rounded border border-stale-border bg-stale-bg px-1.5 py-0.5 font-mono text-xs text-stale-fg">
          STALE
        </span>
      )}
      {freshness === null && (
        <span className="rounded border border-absent-border bg-absent-bg px-1.5 py-0.5 font-mono text-xs text-absent-fg">
          NO DATA
        </span>
      )}
    </span>
  );
}
