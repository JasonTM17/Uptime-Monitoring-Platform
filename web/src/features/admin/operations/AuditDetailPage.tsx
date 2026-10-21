import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { ApiError } from "../../../lib/api/client";
import { useSession } from "../../auth/session";
import { fetchAuditEvent } from "./queries";

const t = (s: string | null | undefined) =>
  s ? new Date(s).toLocaleString() : "—";

// audit:read — single event detail. Read-only: correlation fields and
// the already-redacted safe_diff. There is deliberately no edit,
// delete, or export affordance — audit is append-only evidence.
export function AuditDetailPage() {
  const { user } = useSession();
  const { id } = useParams<{ id: string }>();
  const event = useQuery({
    queryKey: ["admin-audit-event", user?.id, id],
    queryFn: ({ signal }) => fetchAuditEvent(id!, signal),
    enabled: !!id,
  });
  const forbidden =
    event.error instanceof ApiError && event.error.status === 403;
  const ev = event.data;

  return (
    <div className="max-w-2xl space-y-4">
      <header>
        <p className="font-mono text-xs text-fg-muted">
          <Link to="/admin/audit" className="underline hover:text-fg">
            ← audit history
          </Link>
        </p>
        <h1 className="mt-1 text-xl font-semibold">Audit event</h1>
        <p className="mt-1 text-sm text-fg-secondary">
          Read-only record — the diff below was redacted before it was
          written, so secrets never existed in this row.
        </p>
      </header>

      {event.isPending ? (
        <div role="status" className="text-fg-muted">Loading event…</div>
      ) : forbidden ? (
        <div role="alert" className="rounded border border-border bg-container p-3 text-sm text-fg-secondary">
          Your role doesn’t include{" "}
          <code className="font-mono">audit:read</code> — this event is
          denied, not absent.
        </div>
      ) : event.error instanceof ApiError && event.error.status === 404 ? (
        <div role="alert" className="rounded border border-border bg-container p-3 text-sm text-fg-secondary">
          That audit event doesn’t exist.
        </div>
      ) : event.isError || !ev ? (
        <div role="alert" className="rounded border border-down-border bg-down-bg p-3 text-sm text-down-fg">
          Couldn’t load the audit event.{" "}
          <button type="button" onClick={() => event.refetch()} className="underline">
            Retry
          </button>
        </div>
      ) : (
        <article aria-label="Audit event detail" className="space-y-4">
          <dl className="grid grid-cols-1 gap-2 rounded border border-border bg-container p-3 text-sm sm:grid-cols-2">
            <div>
              <dt className="font-mono text-[10px] uppercase tracking-wide text-fg-muted">Action</dt>
              <dd className="font-mono text-xs">{ev.action}</dd>
            </div>
            <div>
              <dt className="font-mono text-[10px] uppercase tracking-wide text-fg-muted">Outcome</dt>
              <dd className="font-mono text-xs">{ev.outcome}</dd>
            </div>
            <div>
              <dt className="font-mono text-[10px] uppercase tracking-wide text-fg-muted">Actor</dt>
              <dd className="font-mono text-xs">
                {ev.actor_kind}
                {ev.actor_id ? ` — ${ev.actor_id}` : " (system)"}
              </dd>
            </div>
            <div>
              <dt className="font-mono text-[10px] uppercase tracking-wide text-fg-muted">Subject</dt>
              <dd className="font-mono text-xs">
                {ev.subject_type} — {ev.subject_id}
              </dd>
            </div>
            <div>
              <dt className="font-mono text-[10px] uppercase tracking-wide text-fg-muted">When</dt>
              <dd className="font-mono text-xs">{t(ev.created_at)}</dd>
            </div>
            <div>
              <dt className="font-mono text-[10px] uppercase tracking-wide text-fg-muted">Request</dt>
              <dd className="font-mono text-xs break-all">{ev.request_id}</dd>
            </div>
          </dl>

          {ev.reason && (
            <section>
              <h2 className="font-mono text-[10px] uppercase tracking-wide text-fg-muted">
                Recorded reason
              </h2>
              <p className="mt-1 rounded border border-border bg-container p-3 text-sm text-fg">
                {ev.reason}
              </p>
            </section>
          )}

          <section>
            <h2 className="font-mono text-[10px] uppercase tracking-wide text-fg-muted">
              Redacted diff
            </h2>
            {ev.diff && Object.keys(ev.diff).length > 0 ? (
              <pre
                tabIndex={0}
                aria-label="Redacted before/after diff"
                className="mt-1 overflow-x-auto rounded border border-border bg-container p-3 font-mono text-xs text-fg"
              >
                {JSON.stringify(ev.diff, null, 2)}
              </pre>
            ) : (
              <p className="mt-1 text-sm text-fg-muted">
                No field-level diff was recorded for this event.
              </p>
            )}
          </section>
        </article>
      )}
    </div>
  );
}
