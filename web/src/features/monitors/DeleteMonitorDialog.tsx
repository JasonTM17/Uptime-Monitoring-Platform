import { useEffect, useRef } from "react";

// Keyboard-complete destructive confirm: Escape cancels, focus lands
// on Cancel, focus returns to the opener on close.
export function DeleteMonitorDialog({
  name,
  open,
  busy,
  onConfirm,
  onCancel,
}: {
  name: string;
  open: boolean;
  busy: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const cancelRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    cancelRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onCancel();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onCancel]);

  if (!open) return null;
  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="del-title"
      className="fixed inset-0 z-10 flex items-center justify-center bg-canvas/80"
    >
      <div className="w-full max-w-sm rounded border border-border bg-container p-4">
        <h2 id="del-title" className="text-base font-semibold">
          Delete “{name}”?
        </h2>
        <p className="mt-1 text-sm text-fg-muted">
          The monitor is removed along with its schedule. History is
          retained. This can’t be undone from the console.
        </p>
        <div className="mt-4 flex justify-end gap-2">
          <button
            ref={cancelRef}
            type="button"
            onClick={onCancel}
            disabled={busy}
            className="rounded border border-border px-3 py-1.5 text-sm text-fg-secondary hover:text-fg"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={busy}
            className="rounded border border-down-border bg-down-bg px-3 py-1.5 text-sm font-medium text-down-fg disabled:bg-disabled-bg disabled:text-disabled-fg"
          >
            {busy ? "Deleting…" : "Delete"}
          </button>
        </div>
      </div>
    </div>
  );
}
