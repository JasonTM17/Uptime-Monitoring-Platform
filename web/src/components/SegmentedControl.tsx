interface Option<T extends string> {
  value: T;
  label: string;
}

/**
 * Segmented pill group (Obsidian "filter pills" pattern). The control keeps an
 * accessible group label while each option is a pressed-state button.
 */
export function SegmentedControl<T extends string>({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: T;
  options: readonly Option<T>[];
  onChange: (v: T) => void;
}) {
  return (
    <div
      role="group"
      aria-label={label}
      className="flex divide-x divide-border overflow-hidden rounded border border-border"
    >
      {options.map((o) => {
        const active = o.value === value;
        return (
          <button
            key={o.value}
            type="button"
            aria-pressed={active}
            onClick={() => onChange(o.value)}
            className={`px-2.5 py-1 font-mono text-xs transition-colors ${
              active
                ? "bg-accent-subtle text-fg"
                : "bg-container text-fg-secondary hover:text-fg"
            }`}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}
