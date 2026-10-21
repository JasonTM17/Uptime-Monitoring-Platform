import { useState } from "react";
import type { Monitor } from "./queries";

export function MonitorActions({
  monitor,
  busy,
  onPause,
  onResume,
  onDelete,
}: {
  monitor: Monitor;
  busy: boolean;
  onPause: () => void;
  onResume: () => void;
  onDelete: () => void;
}) {
  return (
    <div className="flex flex-wrap gap-2" aria-label="Monitor actions">
      {monitor.is_paused ? (
        <button
          type="button"
          disabled={busy}
          onClick={onResume}
          className="rounded border border-up-border bg-up-bg px-2.5 py-1 text-sm text-up-fg disabled:bg-disabled-bg disabled:text-disabled-fg"
        >
          Resume
        </button>
      ) : (
        <button
          type="button"
          disabled={busy}
          onClick={onPause}
          className="rounded border border-paused-border bg-paused-bg px-2.5 py-1 text-sm text-paused-fg disabled:bg-disabled-bg disabled:text-disabled-fg"
        >
          Pause
        </button>
      )}
      <button
        type="button"
        disabled={busy}
        onClick={onDelete}
        className="rounded border border-down-border bg-down-bg px-2.5 py-1 text-sm text-down-fg disabled:bg-disabled-bg disabled:text-disabled-fg"
      >
        Delete…
      </button>
    </div>
  );
}

export function useActionGuard() {
  const [busy, setBusy] = useState(false);
  const guard = async (fn: () => Promise<unknown>) => {
    if (busy) return;
    setBusy(true);
    try {
      await fn();
    } finally {
      setBusy(false);
    }
  };
  return { busy, guard };
}
