const SEC = 1000;
const MIN = 60 * SEC;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

/** "8m 42s" / "1h 5m" / "2d 3h" — compact two-unit duration. */
export function formatDuration(from: string, to: string | null | undefined): string {
  const start = new Date(from).getTime();
  const end = to ? new Date(to).getTime() : Date.now();
  const d = Math.max(0, end - start);
  if (d < MIN) return `${Math.floor(d / SEC)}s`;
  if (d < HOUR) return `${Math.floor(d / MIN)}m ${Math.floor((d % MIN) / SEC)}s`;
  if (d < DAY) return `${Math.floor(d / HOUR)}h ${Math.floor((d % HOUR) / MIN)}m`;
  return `${Math.floor(d / DAY)}d ${Math.floor((d % DAY) / HOUR)}h`;
}

/** "4s ago" / "3m ago" / "2h ago" / "5d ago" — relative age for the console table. */
export function relTime(iso: string, now = Date.now()): string {
  const d = Math.max(0, now - new Date(iso).getTime());
  if (d < MIN) return `${Math.floor(d / SEC)}s ago`;
  if (d < HOUR) return `${Math.floor(d / MIN)}m ago`;
  if (d < DAY) return `${Math.floor(d / HOUR)}h ago`;
  return `${Math.floor(d / DAY)}d ago`;
}

/** "in 41s" / "in 3m" — countdown to a scheduled time. */
export function relTimeUntil(iso: string, now = Date.now()): string {
  const d = Math.max(0, new Date(iso).getTime() - now);
  if (d < MIN) return `${Math.floor(d / SEC)}s`;
  if (d < HOUR) return `${Math.floor(d / MIN)}m`;
  if (d < DAY) return `${Math.floor(d / HOUR)}h`;
  return `${Math.floor(d / DAY)}d`;
}
