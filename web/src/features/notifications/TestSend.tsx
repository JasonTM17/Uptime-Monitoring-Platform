import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { ApiError } from "../../lib/api/client";
import { ReauthDialog } from "../../components/ReauthDialog";
import { useSession } from "../auth/session";
import { fetchMonitors } from "../dashboard/queries";
import { testChannel, type Channel } from "./queries";

// Explicit test-send: queues one TEST intent against an owned monitor the
// channel is bound to. 202 means queued — never delivered. A stale
// session triggers the step-up dialog, then the send can be retried.
export function TestSend({ channel }: { channel: Channel }) {
  const { user } = useSession();
  const [monitorId, setMonitorId] = useState("");
  const [busy, setBusy] = useState(false);
  const [reauth, setReauth] = useState(false);
  const [note, setNote] = useState<{ tone: "ok" | "err"; text: string } | null>(
    null,
  );
  const monitors = useQuery({
    queryKey: ["monitors", user?.id, "testsend"],
    queryFn: ({ signal }) => fetchMonitors({}, null, signal),
    staleTime: 30_000,
  });
  const list = monitors.data?.items ?? [];
  const canTest = channel.status === "VERIFIED" && channel.enabled;

  const send = async () => {
    if (busy || !monitorId) return;
    setBusy(true);
    setNote(null);
    try {
      const r = await testChannel(channel.id!, monitorId);
      setNote(
        r.kind === "deduplicated"
          ? { tone: "ok", text: "A test is already queued for this channel — the earlier intent stands." }
          : {
              tone: "ok",
              text: `Queued — state ${r.state ?? "PENDING"}. The dispatcher will claim and send it; check Telegram for receipt.`,
            },
      );
    } catch (e) {
      if (e instanceof ApiError && e.status === 403 && e.code === "REAUTH_REQUIRED") {
        setReauth(true);
      } else if (e instanceof ApiError && e.status === 429) {
        setNote({ tone: "err", text: "Test sends are rate-limited — wait before trying again." });
      } else if (e instanceof ApiError && e.status === 409) {
        setNote({
          tone: "err",
          text: "This channel isn’t bound to that monitor (or isn’t verified). Bind it on the monitor page first.",
        });
      } else if (e instanceof ApiError && e.status === 404) {
        setNote({ tone: "err", text: "Monitor or channel not found." });
      } else {
        setNote({ tone: "err", text: "Couldn’t queue the test." });
      }
    } finally {
      setBusy(false);
    }
  };

  if (!canTest) {
    return (
      <p className="text-xs text-fg-muted">
        {channel.status === "PENDING_VERIFICATION"
          ? "Awaiting operator verification — test-send unlocks once the destination is verified."
          : "Disabled channels can’t receive tests."}
      </p>
    );
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      <label className="text-xs text-fg-muted">
        Monitor
        <select
          value={monitorId}
          onChange={(e) => setMonitorId(e.target.value)}
          className="ml-1 rounded border border-border bg-bg px-1.5 py-0.5 text-xs text-fg"
        >
          <option value="">—</option>
          {list.map((m) => (
            <option key={m.id} value={m.id}>
              {m.name}
            </option>
          ))}
        </select>
      </label>
      <button
        type="button"
        onClick={send}
        disabled={busy || !monitorId}
        className="rounded border border-border px-2 py-0.5 text-xs text-fg-secondary hover:text-fg disabled:text-disabled-fg"
      >
        {busy ? "Queueing…" : "Send test"}
      </button>
      {note && (
        <p
          role="status"
          className={note.tone === "ok" ? "text-xs text-ok-fg" : "text-xs text-down-fg"}
        >
          {note.text}
        </p>
      )}
      <ReauthDialog
        open={reauth}
        reason="Sending a test notification requires a recently confirmed password."
        onCancel={() => setReauth(false)}
        onSuccess={() => {
          setReauth(false);
          setNote({ tone: "ok", text: "Verified — press Send test again to queue it." });
        }}
      />
    </div>
  );
}
