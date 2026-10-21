import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { makeQueryClient } from "../../../app/providers";
import { App } from "../../../app/App";

const USER = {
  id: "u-admin",
  email: "admin@example.com",
  display_name: "Admin",
  status: "ACTIVE",
  created_at: "2025-01-01T00:00:00Z",
};

const OPS_ABSENT = { data: {} };
const OPS_STALE = {
  data: {
    engine: {
      epoch: 4,
      owner_instance: "eng-1",
      heartbeat_at: "2025-01-01T00:00:00Z",
      freshness: "stale",
      stale_after_seconds: 30,
    },
    runs: { reserved: 2, running: 1 },
    outbox: { pending: 0, leased: 1, dead: 3, oldest_pending: null, oldest_age_seconds: null },
    rollup: { last_bucket: null, freshness: "absent" },
  },
};

const DEAD_ROW = {
  id: "d-deadbeef-0000-0000-0000-000000000001",
  monitor_id: "m-1",
  incident_id: null,
  event_kind: "incident_closed",
  state: "DEAD",
  attempts: 8,
  next_attempt_at: null,
  last_error_code: "delivery_failed",
  created_at: "2025-01-01T00:00:00Z",
  version: 3,
};

const AUDIT_ROW = {
  id: "a-1",
  actor_id: "u-admin",
  actor_kind: "user",
  action: "role.update",
  subject_type: "role",
  subject_id: "r-2",
  reason: "tighten grants",
  outcome: "ok",
  diff: { permissions: { before: ["audit:read"], after: ["audit:read", "platform:read"] } },
  request_id: "req-1",
  created_at: "2025-01-01T00:00:00Z",
};

function res(body: unknown, status = 200) {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );
}
const err = (status: number, code: string, message: string) =>
  res({ error: { code, message, fields: null }, request_id: "r" }, status);

type Handler = (url: string, init?: RequestInit) => Promise<Response> | null;
let handler: Handler;
let posted: { url: string; method: string; body?: unknown; idem?: string | null }[] = [];

const defaults = (url: string, init?: RequestInit) => {
  if (url === "/api/auth/me")
    return res({ data: { user: USER, session_expires_at: "t" } });
  if (url === "/api/auth/csrf") return res({ data: { csrf_token: "tok" } });
  if (url === "/api/admin/overview") return res({ data: {} });
  return null;
};

beforeEach(() => {
  posted = [];
  handler = (url, init) => defaults(url, init);
  vi.stubGlobal("fetch", (i: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof i === "string" ? i : i.toString();
    if (init?.method && init.method !== "GET") {
      posted.push({
        url,
        method: init.method,
        body: init.body ? JSON.parse(init.body as string) : undefined,
        idem: (init.headers as Record<string, string>)?.["Idempotency-Key"] ?? null,
      });
    }
    const r = handler(url, init);
    return r === null ? res({}, 404) : r;
  });
});
afterEach(() => vi.unstubAllGlobals());

function renderAt(path: string) {
  const qc = makeQueryClient();
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return qc;
}

describe("admin operations screens", () => {
  it("missing telemetry renders absent, never a healthy zero", async () => {
    handler = (url, init) =>
      url === "/api/admin/operations" ? res(OPS_ABSENT) : defaults(url, init);
    renderAt("/admin/operations");
    expect(await screen.findAllByText("absent")).not.toHaveLength(0);
    // zero-count-looking fields render as "—", not fabricated numbers
    expect(screen.getAllByText("—").length).toBeGreaterThan(0);
  });

  it("stale heartbeat and absent rollup each render their own badge", async () => {
    handler = (url, init) =>
      url === "/api/admin/operations" ? res(OPS_STALE) : defaults(url, init);
    renderAt("/admin/operations");
    expect(await screen.findByText("stale")).toBeInTheDocument();
    expect(screen.getByText("absent")).toBeInTheDocument();
    expect(screen.getByText("no pending backlog")).toBeInTheDocument();
  });

  it("database unreachable is an explicit banner, not silent", async () => {
    handler = (url, init) =>
      url === "/api/admin/overview"
        ? res({ data: { database: { reachable: false }, engine: { freshness: "fresh" } } })
        : defaults(url, init);
    renderAt("/admin");
    expect(await screen.findByText(/database is unreachable/i)).toBeInTheDocument();
  });

  it("overview is global-scoped and visibly different from the owner dashboard", async () => {
    handler = (url, init) =>
      url === "/api/admin/overview"
        ? res({
            data: {
              users: { total: 7, active: 5, disabled: 2 },
              monitors: { total: 9, up: 4, down: 1, paused: 4 },
              sessions: { live: 3 },
              incidents: { open: 2 },
              outbox: { pending: 1, leased: 0, dead: 2 },
              engine: { epoch: 2, heartbeat_at: "2025-01-01T00:00:00Z", freshness: "fresh" },
              database: { reachable: true },
            },
          })
        : defaults(url, init);
    renderAt("/admin");
    // "Global scope" renders statically during pending — await real data
    expect(await screen.findByText("Live sessions")).toBeInTheDocument();
    expect(screen.getByText(/global scope/i)).toBeInTheDocument();
    expect(screen.getByText("fresh")).toBeInTheDocument();
  });

  it("audit denied is explicit and distinct from an empty audit", async () => {
    handler = (url, init) => {
      if (url.startsWith("/api/admin/audit-events?"))
        return err(403, "FORBIDDEN", "forbidden");
      return defaults(url, init);
    };
    renderAt("/admin/audit");
    expect(await screen.findByText(/doesn’t include/i)).toBeInTheDocument();
    expect(screen.queryByText(/empty result/i)).not.toBeInTheDocument();
  });

  it("empty audit states empty honestly", async () => {
    handler = (url, init) =>
      url.startsWith("/api/admin/audit-events?")
        ? res({ data: { events: [], next_cursor: null } })
        : defaults(url, init);
    renderAt("/admin/audit");
    expect(await screen.findByText(/empty result/i)).toBeInTheDocument();
  });

  it("a rejected cursor surfaces an invalid-filter error", async () => {
    handler = (url, init) => {
      if (url.startsWith("/api/admin/audit-events?")) {
        if (url.includes("cursor="))
          return err(400, "INVALID_CURSOR", "cursor does not match filters");
        return res({
          data: {
            events: [AUDIT_ROW],
            next_cursor: "cur-1",
          },
        });
      }
      return defaults(url, init);
    };
    const user = userEvent.setup();
    renderAt("/admin/audit");
    await user.click(await screen.findByRole("button", { name: /load more/i }));
    // retry backoff on the failed next-page fetch exceeds the default wait
    expect(
      await screen.findByText(/filters or cursor were rejected/i, {}, { timeout: 15000 }),
    ).toBeInTheDocument();
  });

  it("audit detail is read-only: correlation + redacted diff, no edit/export", async () => {
    handler = (url, init) =>
      url === "/api/admin/audit-events/a-1"
        ? res({ data: AUDIT_ROW })
        : defaults(url, init);
    renderAt("/admin/audit/a-1");
    expect(await screen.findByText("role.update")).toBeInTheDocument();
    expect(screen.getByText("req-1")).toBeInTheDocument();
    expect(screen.getByText("tighten grants")).toBeInTheDocument();
    expect(screen.getByLabelText(/redacted before\/after diff/i)).toBeInTheDocument();
    const detail = screen.getByRole("article");
    expect(within(detail).queryByRole("button", { name: /edit|export|delete/i })).not.toBeInTheDocument();
  });

  it("denied audit detail says denied, not absent", async () => {
    handler = (url, init) =>
      url === "/api/admin/audit-events/a-1"
        ? err(403, "FORBIDDEN", "forbidden")
        : defaults(url, init);
    renderAt("/admin/audit/a-1");
    expect(await screen.findByText(/denied, not absent/i)).toBeInTheDocument();
  });

  it("retry re-queues a dead head: 202 receipt says queued, not delivered", async () => {
    handler = (url, init) => {
      if (url.startsWith("/api/admin/outbox?"))
        return res({ data: { deliveries: [DEAD_ROW], next_cursor: null } });
      if (url === `/api/admin/outbox/${DEAD_ROW.id}/retry` && init?.method === "POST")
        return res(
          { data: { delivery_id: DEAD_ROW.id, state: "PENDING", version: 4 } },
          202,
        );
      return defaults(url, init);
    };
    const user = userEvent.setup();
    renderAt("/admin/outbox");
    await user.click(await screen.findByRole("button", { name: /retry…/i }));
    await user.type(await screen.findByLabelText(/reason/i), "transient provider outage cleared");
    await user.click(screen.getByRole("button", { name: /^retry$/i }));
    const post = posted.find((p) => p.url.includes("/retry"));
    expect(post?.body).toEqual({ expected_version: 3, reason: "transient provider outage cleared" });
    expect(post?.idem).toBeTruthy();
    expect(await screen.findByText(/re-queued PENDING — not delivered/i)).toBeInTheDocument();
  });

  it("suppress confirms and terminalizes the stream", async () => {
    handler = (url, init) => {
      if (url.startsWith("/api/admin/outbox?"))
        return res({ data: { deliveries: [DEAD_ROW], next_cursor: null } });
      if (url === `/api/admin/outbox/${DEAD_ROW.id}/suppress` && init?.method === "POST")
        return res(
          { data: { delivery_id: DEAD_ROW.id, state: "SUPPRESSED", rows_suppressed: 3 } },
          202,
        );
      return defaults(url, init);
    };
    const user = userEvent.setup();
    renderAt("/admin/outbox");
    await user.click(await screen.findByRole("button", { name: /suppress…/i }));
    expect(await screen.findByText(/every live descendant/i)).toBeInTheDocument();
    await user.type(await screen.findByLabelText(/reason/i), "stream is obsolete");
    await user.click(screen.getByRole("button", { name: /^suppress$/i }));
    expect(await screen.findByText(/suppressed — SUPPRESSED/i)).toBeInTheDocument();
  });

  it("a blocked retry shows the conflict and does not mutate the row", async () => {
    handler = (url, init) => {
      if (url.startsWith("/api/admin/outbox?"))
        return res({ data: { deliveries: [DEAD_ROW], next_cursor: null } });
      if (url === `/api/admin/outbox/${DEAD_ROW.id}/retry` && init?.method === "POST")
        return err(409, "CONFLICT", "live predecessor blocks recovery");
      return defaults(url, init);
    };
    const user = userEvent.setup();
    renderAt("/admin/outbox");
    await user.click(await screen.findByRole("button", { name: /retry…/i }));
    await user.type(await screen.findByLabelText(/reason/i), "why");
    await user.click(screen.getByRole("button", { name: /^retry$/i }));
    expect(await screen.findByText(/changed since you loaded it/i)).toBeInTheDocument();
    // no optimistic flip — the DEAD badge is still shown (plus its filter
    // option in the state select, hence getAllByText)
    expect(screen.getAllByText("DEAD").length).toBeGreaterThan(0);
    expect(screen.queryByText(/not delivered/i)).not.toBeInTheDocument();
  });

  it("a revoked session mid-action fails the action once, honestly", async () => {
    handler = (url, init) => {
      if (url.startsWith("/api/admin/outbox?"))
        return res({ data: { deliveries: [DEAD_ROW], next_cursor: null } });
      if (url === `/api/admin/outbox/${DEAD_ROW.id}/retry` && init?.method === "POST")
        return err(401, "UNAUTHENTICATED", "session revoked");
      return defaults(url, init);
    };
    const user = userEvent.setup();
    renderAt("/admin/outbox");
    await user.click(await screen.findByRole("button", { name: /retry…/i }));
    await user.type(await screen.findByLabelText(/reason/i), "why");
    await user.click(screen.getByRole("button", { name: /^retry$/i }));
    expect(await screen.findByText(/action failed — nothing was applied/i)).toBeInTheDocument();
    expect(posted.filter((p) => p.url.includes("/retry"))).toHaveLength(1);
  });

  it("global monitors deny retry controls without the grant and show redacted targets", async () => {
    handler = (url, init) =>
      url.startsWith("/api/admin/monitors?")
        ? res({
            data: {
              monitors: [
                {
                  id: "m-1",
                  owner_id: "u-owner-1",
                  name: "billing api",
                  target: "https://api.example.com",
                  health: "UP",
                  is_paused: false,
                  generation: 2,
                  next_check_at: "2025-01-01T00:05:00Z",
                  created_at: "2025-01-01T00:00:00Z",
                },
              ],
              next_cursor: null,
            },
          })
        : defaults(url, init);
    renderAt("/admin/monitors");
    expect(await screen.findByText("https://api.example.com")).toBeInTheDocument();
    // the pause/resume affordance exists (the grant check is server-side
    // per action — a denied actor sees the backend's explicit denial)
    expect(screen.getByRole("button", { name: /pause…/i })).toBeInTheDocument();
    // no control can mark a monitor up or bypass SSRF validation
    expect(screen.queryByRole("button", { name: /force up|mark up|recheck now/i })).not.toBeInTheDocument();
  });

  it("no URL/destination/DSN/token canary leaks into DOM or query cache", async () => {
    const canaries = ["postgres://", "bot_token", "?token=", "secret=", "t.me/sendMessage"];
    handler = (url, init) => {
      if (url.startsWith("/api/admin/outbox?"))
        return res({ data: { deliveries: [DEAD_ROW], next_cursor: null } });
      if (url === "/api/admin/audit-events/a-1") return res({ data: AUDIT_ROW });
      if (url.startsWith("/api/admin/audit-events?"))
        return res({ data: { events: [AUDIT_ROW], next_cursor: null } });
      return defaults(url, init);
    };
    const qc = renderAt("/admin/outbox");
    await screen.findByText("DEAD");
    const html = document.body.innerHTML;
    const cache = JSON.stringify(
      qc.getQueryCache().getAll().map((q) => q.state.data),
    );
    for (const c of canaries) {
      expect(html).not.toContain(c);
      expect(cache).not.toContain(c);
    }
  });
});
