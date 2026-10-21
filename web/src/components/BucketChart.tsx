import type { StatsBucket } from "../features/monitor-detail/queries";

// Hand-rolled SVG bar chart — deterministic, no dependency, honors
// reduced motion by having no animation at all. Buckets without
// evidence render as explicit gaps, never interpolated.
export function BucketChart({ buckets }: { buckets: StatsBucket[] }) {
  const W = 640;
  const H = 120;
  const pad = 2;
  const max = Math.max(1, ...buckets.map((b) => b.valid_samples ?? 0));
  const step = buckets.length > 0 ? W / buckets.length : W;
  const barW = Math.max(1, step - pad);

  return (
    <svg
      role="img"
      aria-label="Per-bucket check outcomes — see the data table for exact values"
      viewBox={`0 0 ${W} ${H}`}
      className="h-28 w-full"
      preserveAspectRatio="none"
    >
      {buckets.map((b, i) => {
        const ok = b.successes ?? 0;
        const bad = b.failures ?? 0;
        const total = Math.max(0, b.valid_samples ?? 0);
        const hOk = (ok / max) * H;
        const hBad = (bad / max) * H;
        const x = i * step;
        return (
          <g key={b.bucket_start ?? i}>
            <title>
              {`${b.bucket_start ?? "bucket"}: ${ok} ok, ${bad} failed, ${total} sampled`}
            </title>
            {total === 0 ? (
              // gap marker — evidence absent, not a zero-height success
              <rect
                x={x}
                y={H - 2}
                width={barW}
                height={2}
                className="fill-chart-nodata"
              />
            ) : (
              <>
                <rect
                  x={x}
                  y={H - hOk}
                  width={barW}
                  height={hOk}
                  className="fill-chart-ok"
                />
                <rect
                  x={x}
                  y={H - hOk - hBad}
                  width={barW}
                  height={hBad}
                  className="fill-chart-outage"
                />
              </>
            )}
          </g>
        );
      })}
    </svg>
  );
}
