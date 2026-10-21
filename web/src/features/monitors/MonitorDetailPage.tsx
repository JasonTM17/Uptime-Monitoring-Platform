import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { HealthBadge } from "../../components/HealthBadge";
import { ApiError } from "../../lib/api/client";
import { useSession } from "../auth/session";
import { AvailabilityPanel } from "../monitor-detail/AvailabilityPanel";
import { ChecksTable } from "../monitor-detail/ChecksTable";
import { StatsPanel } from "../monitor-detail/StatsPanel";
import { DeleteMonitorDialog } from "./DeleteMonitorDialog";
import { MonitorActions, useActionGuard } from "./MonitorActions";
import { MonitorForm, type MonitorFormValues } from "./MonitorForm";
import {
  deleteMonitor,
  getMonitor,
  listChannels,
  pauseMonitor,
  patchMonitor,
  replaceChannels,
  resumeMonitor,
} from "./queries";

function toForm(m: NonNullable<Awaited<ReturnType<typeof getMonitor>>>) {
  return {
    name: m.name,
    target_url: m.target_url,
    interval_seconds: m.interval_seconds,
    timeout_seconds: m.timeout_seconds,
    expected_status: m.expected_status ?? null,
  };
}

export function MonitorDetailPage() {
  const { id = "" } = useParams();
  const { user } = useSession();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [conflict, setConflict] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [confirmDel, setConfirmDel] = useState(false);
  const { busy, guard } = useActionGuard();
  const [selected, setSelected] = useState<string[]>([]);
  const [bindMsg, setBindMsg] = useState<string | null>(null);

  const detail = useQuery({
    queryKey: ["monitor", user?.id, id],
    queryFn: ({ signal }) => getMonitor(id, signal),
    enabled: !!id,
  });
  const channels = useQuery({
    queryKey: ["channels", user?.id],
    queryFn: ({ signal }) => listChannels(signal),
  });

  const m = detail.data ?? null;

  const invalidate = () =>
    Promise.all([
      qc.invalidateQueries({ queryKey: ["monitor", user?.id, id] }),
      qc.invalidateQueries({ queryKey: ["monitors", user?.id] }),
      qc.invalidateQueries({ queryKey: ["dashboard-summary", user?.id] }),
    ]);

  const onApiError = (e: unknown) => {
    if (e instanceof ApiError && e.status === 409 && e.code === "GENERATION_CONFLICT") {
      setConflict(true);
    } else if (e instanceof ApiError) {
      setActionError(e.message);
    } else {
      setActionError("Request failed — check your connection.");
    }
  };

  const patch = useMutation({
    mutationFn: (body: Parameters<typeof patchMonitor>[1]) =>
      patchMonitor(id, body),
  });
  const pause = useMutation({ mutationFn: () => pauseMonitor(id, m!.generation) });
  const resume = useMutation({ mutationFn: () => resumeMonitor(id, m!.generation) });
  const del = useMutation({
    mutationFn: () => deleteMonitor(id, m!.generation),
  });
  const bind = useMutation({
    mutationFn: () => replaceChannels(id, m!.generation, selected),
  });

  const submitEdit = async (v: MonitorFormValues) => {
    if (!m) return;
    setActionError(null);
    try {
      await patch.mutateAsync({
        expected_generation: m.generation,
        name: v.name.trim(),
        target_url: v.target_url.trim(),
        interval_seconds: v.interval_seconds,
        timeout_seconds: v.timeout_seconds,
        expected_status: v.expected_status,
      });
      setConflict(false);
      await invalidate();
    } catch (e) {
      onApiError(e);
      if (!(e instanceof ApiError && e.status === 409)) throw e;
    }
  };

  const act = (fn: () => Promise<unknown>, after?: () => void) =>
    guard(async () => {
      setActionError(null);
      try {
        await fn();
        await invalidate();
        after?.();
      } catch (e) {
        onApiError(e);
      }
    });

  const eligible = (channels.data ?? []).filter(
    (c) => c.status === "VERIFIED" && c.enabled,
  );

  return (
    <div className="flex flex-col gap-4">
      {detail.isPending ? (
        <div role="status" className="text-fg-muted">Loading monitor…</div>
      ) : detail.isError || !m ? (
        <div role="alert" className="rounded border border-down-border bg-down-bg p-3 text-sm text-down-fg">
          {detail.error instanceof ApiError && detail.error.status === 404
            ? "Monitor not found."
            : "Couldn’t load this monitor."}{" "}
          <button type="button" onClick={() => detail.refetch()} className="underline">
            Retry
          </button>
        </div>
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-lg font-semibold">{m.name}</h1>
            <HealthBadge
              health={m.health}
              isPaused={m.is_paused}
              freshness={m.freshness}
            />
            <span className="ml-auto font-mono text-xs text-fg-muted">
              gen {m.generation}
            </span>
          </div>
          <p className="font-mono text-xs text-fg-muted break-all">{m.target_url}</p>

          <MonitorActions
            monitor={m}
            busy={busy}
            onPause={() => void act(() => pause.mutateAsync())}
            onResume={() => void act(() => resume.mutateAsync())}
            onDelete={() => setConfirmDel(true)}
          />
          {actionError && (
            <p role="alert" className="text-sm text-down-fg">{actionError}</p>
          )}

          <section aria-label="Edit monitor">
            <h2 className="mb-2 text-sm font-medium text-fg-secondary">Edit</h2>
            <MonitorForm
              initial={toForm(m)}
              onSubmit={submitEdit}
              submitLabel="Save changes"
              generationConflict={conflict}
              onDismissConflict={async () => {
                await detail.refetch();
                setConflict(false);
              }}
            />
          </section>

          <section aria-label="Channel bindings" className="max-w-lg">
            <h2 className="mb-1 text-sm font-medium text-fg-secondary">
              Notification channels
            </h2>
            <p className="mb-2 text-xs text-fg-muted">
              The API replaces the full binding set and does not expose
              current bindings — your saved selection overwrites whatever
              is bound.
            </p>
            {channels.isPending ? (
              <div role="status" className="text-fg-muted">Loading channels…</div>
            ) : eligible.length === 0 ? (
              <p className="text-sm text-fg-muted">
                No verified, enabled channels yet.
              </p>
            ) : (
              <fieldset className="flex flex-col gap-1">
                <legend className="sr-only">Channels to bind</legend>
                {eligible.map((c) => (
                  <label key={c.id} className="flex items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={selected.includes(c.id)}
                      onChange={(e) =>
                        setSelected((s) =>
                          e.target.checked
                            ? [...s, c.id]
                            : s.filter((x) => x !== c.id),
                        )
                      }
                    />
                    {c.label}
                    <span className="font-mono text-xs text-fg-muted">
                      {c.destination_mask ?? ""}
                    </span>
                  </label>
                ))}
                <div className="mt-2">
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() =>
                      void act(async () => {
                        const res = await bind.mutateAsync();
                        setBindMsg(
                          `Bindings saved — generation ${res.data?.generation ?? "?"}`,
                        );
                      })
                    }
                    className="rounded border border-border px-2.5 py-1 text-sm text-fg-secondary hover:text-fg disabled:text-disabled-fg"
                  >
                    Save bindings
                  </button>
                  {bindMsg && (
                    <span role="status" className="ml-2 text-xs text-up-fg">
                      {bindMsg}
                    </span>
                  )}
                </div>
              </fieldset>
            )}
          </section>

          <StatsPanel monitorId={m.id} />
          <AvailabilityPanel monitorId={m.id} />
          <ChecksTable monitorId={m.id} />

          <DeleteMonitorDialog
            name={m.name}
            open={confirmDel}
            busy={busy}
            onCancel={() => setConfirmDel(false)}
            onConfirm={() =>
              void act(() => del.mutateAsync(), () => navigate("/", { replace: true }))
            }
          />
        </>
      )}
    </div>
  );
}
