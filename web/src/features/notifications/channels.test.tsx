import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { makeQueryClient } from "../../app/providers";
import { App } from "../../app/App";

const USER = {
  id: "u-1",
  email: "u@example.com",
  display_name: "U",
  status: "ACTIVE",
  created_at: "2025-01-01T00:00:00Z",
};

const VERIFIED = {
  id: "c-1",
  label: "on-call",
  kind: "TELEGRAM",
  status: "VERIFIED",
  enabled: true,
  destination_mask: "•••5123",
  verified_at: "2025-01-01T00:00:00Z",
  version: 2,
  created_at: "2025-01-01T00:00:00Z",
  updated_at: "2025-01-01T00:00:00Z",
};

const PENDING = { ...VERIFIED, id: "c-2", label: "pending-ch", status: "PENDING_VERIFICATION", destination_mask: null, verified_at: null, version: 1 };
const DISABLED = { ...VERIFIED, id: "c-3", label: "old-ch", status: "DISABLED", enabled: false, version: 4 };

function res(body: unknown, status = 200) {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );
}
const err = (status: number, code: string, message: string, fields?: Record<string, string>) =>
  res({ error: { code, message, fields }, request_id: "r" }, status);

type Handler = (url: string, init?: RequestInit) => Promise<Response> | null;
let handler: Handler;
let channels: object[] = [];

const defaults = (url: string, init?: RequestInit) => {
  if (url === "/api/auth/me")
    return res({ data: { user: USER, session_expires_at: "t" } });
  if (url === "/api/admin/overview") return res({}, 403);
  if (url === "/api/auth/csrf") return res({ data: { csrf_token: "tok" } });
  if (url === "/api/notification-channels" && init?.method === "GET")
    return res({ data: { items: channels } });
  if (url === "/api/monitors" || url.startsWith("/api/monitors?"))
    return res({
      data: {
        items: [
          { id: "m-1", name: "site", target_url: "https://example.com", method: "GET", interval_seconds: 300, timeout_seconds: 5, expected_status: 200, is_paused: false, health: "UP", generation: 1, created_at: "t", updated_at: "t" },
        ],
        has_more: false,
        next_cursor: null,
      },
    });
  if (url === "/api/dashboard/summary")
    return res({
      data: {
        monitors: 1, active: 1, paused: 0, up: 1, down: 0,
        open_incidents: 1,
        sample_uptime_24h: 0.99,
        recent_incidents: [
          { id: "i-1", monitor_id: "m-1", monitor_name: "site", opened_at: "2025-01-01T00:00:00Z", resolved_at: null, close_reason: null },
        ],
        quota: { used: 1, active: 1, paused: 0, limit: 5, profile: "local", as_of: "t", source: "server" },
        as_of: "t",
      },
    });
  return null;
};

let posted: { url: string; body?: unknown }[] = [];
beforeEach(() => {
  posted = [];
  channels = [VERIFIED, PENDING, DISABLED];
  handler = (url, init) => defaults(url, init);
  vi.stubGlobal("fetch", (i: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof i === "string" ? i : i.toString();
    if (init?.method && init.method !== "GET") {
      posted.push({ url, body: init.body ? JSON.parse(init.body as string) : undefined });
    }
    const r = handler(url, init);
    return r === null ? res({}, 404) : r;
  });
});
afterEach(() => vi.unstubAllGlobals());

function renderAt(path: string) {
  return render(
    <QueryClientProvider client={makeQueryClient()}>
      <MemoryRouter initialEntries={[path]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

async function pickMonitorAndSend() {
  const user = userEvent.setup();
  await user.selectOptions(await screen.findByLabelText(/^Monitor$/i), "m-1");
  await user.click(screen.getByRole("button", { name: /send test/i }));
}

describe("channels page", () => {
  it("lists lifecycle states with masked destination only", async () => {
    renderAt("/channels");
    expect(await screen.findByText("on-call")).toBeInTheDocument();
    expect(screen.getByText("verified")).toBeInTheDocument();
    expect(screen.getByText("pending verification")).toBeInTheDocument();
    expect(screen.getByText("disabled")).toBeInTheDocument();
    // mask survives; nothing resembling a chat id or token renders
    expect(screen.getAllByText("•••5123").length).toBeGreaterThan(0);
    expect(screen.queryByText(/5123[^•]/)).not.toBeInTheDocument();
  });

  it("blocks test-send on pending and disabled channels", async () => {
    renderAt("/channels");
    await screen.findByText("on-call");
    // only the verified+enabled row gets a Send test control
    const sendButtons = screen.getAllByRole("button", { name: /send test/i });
    expect(sendButtons).toHaveLength(1);
    expect(
      screen.getByText(/awaiting operator verification/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/disabled channels can’t receive tests/i),
    ).toBeInTheDocument();
  });

  it("test-send posts monitor_id and reports queued semantics, not sent", async () => {
    handler = (url, init) =>
      url === "/api/notification-channels/c-1/test" && init?.method === "POST"
        ? res({ data: { intent_id: "in-1", state: "PENDING", queued: true } }, 202)
        : defaults(url, init);
    renderAt("/channels");
    await pickMonitorAndSend();
    expect(await screen.findByText(/queued/i)).toBeInTheDocument();
    expect(screen.queryByText(/sent|delivered/i)).not.toBeInTheDocument();
    const test = posted.find((p) => p.url.includes("/test"));
    expect(test?.body).toEqual({ monitor_id: "m-1" });
  });

  it("duplicate-window 200 reports the earlier intent stands", async () => {
    handler = (url, init) =>
      url === "/api/notification-channels/c-1/test" && init?.method === "POST"
        ? res({ data: { deduplicated: true, queued: true } })
        : defaults(url, init);
    renderAt("/channels");
    await pickMonitorAndSend();
    expect(await screen.findByText(/already queued/i)).toBeInTheDocument();
  });

  it("409 explains the channel isn't bound; 429 reports rate limiting", async () => {
    handler = (url, init) =>
      url === "/api/notification-channels/c-1/test" && init?.method === "POST"
        ? err(409, "CONFLICT", "channel not bound to monitor")
        : defaults(url, init);
    renderAt("/channels");
    await pickMonitorAndSend();
    expect(await screen.findByText(/isn’t bound/i)).toBeInTheDocument();

    handler = (url, init) =>
      url === "/api/notification-channels/c-1/test" && init?.method === "POST"
        ? err(429, "RATE_LIMITED", "rate limit")
        : defaults(url, init);
    await pickMonitorAndSend();
    expect(await screen.findByText(/rate-limited/i)).toBeInTheDocument();
  });

  it("403 REAUTH_REQUIRED opens step-up, not a blind retry", async () => {
    let authed = false;
    handler = (url, init) => {
      if (url === "/api/notification-channels/c-1/test" && init?.method === "POST")
        return authed
          ? res({ data: { intent_id: "x", state: "PENDING", queued: true } }, 202)
          : err(403, "REAUTH_REQUIRED", "recent authentication required");
      if (url === "/api/auth/reauth" && init?.method === "POST") {
        authed = true;
        return res({ data: { reauthenticated_until: "t" } });
      }
      return defaults(url, init);
    };
    const user = userEvent.setup();
    renderAt("/channels");
    await pickMonitorAndSend();
    expect(await screen.findByText(/confirm it’s you/i)).toBeInTheDocument();
    await user.type(screen.getByLabelText(/password/i), "pw");
    await user.click(screen.getByRole("button", { name: /continue/i }));
    expect(await screen.findByText(/press send test again/i)).toBeInTheDocument();
    // no automatic resend — the user explicitly retries
    const tests = posted.filter((p) => p.url.includes("/test"));
    expect(tests).toHaveLength(1);
  });

  it("create posts label only and reports allocation 409 by scope", async () => {
    handler = (url, init) =>
      url === "/api/notification-channels" && init?.method === "POST"
        ? err(409, "ALLOCATION_LIMIT_REACHED", "pending channel limit reached", { scope: "pending_channels" })
        : defaults(url, init);
    const user = userEvent.setup();
    renderAt("/channels");
    await user.type(await screen.findByLabelText(/channel label/i), "new");
    await user.click(screen.getByRole("button", { name: /^create$/i }));
    expect(await screen.findByText(/pending channel limit reached/i)).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent(/deleting pending channels does not free this limit/i);
    const post = posted.find((p) => p.url === "/api/notification-channels");
    expect(post?.body).toEqual({ label: "new" });
  });
});

describe("incidents page", () => {
  it("renders the bounded recent strip with open/resolved states", async () => {
    renderAt("/incidents");
    expect(await screen.findByText("site")).toBeInTheDocument();
    expect(screen.getByText("open")).toBeInTheDocument();
    expect(screen.getByText(/currently open/)).toBeInTheDocument();
  });

  it("renders the honest empty state", async () => {
    handler = (url, init) => {
      if (url === "/api/dashboard/summary")
        return res({
          data: {
            monitors: 0, active: 0, paused: 0, up: 0, down: 0,
            open_incidents: 0, sample_uptime_24h: null,
            recent_incidents: [],
            quota: { used: 0, active: 0, paused: 0, limit: 5, profile: "local", as_of: "t", source: "server" },
            as_of: "t",
          },
        });
      return defaults(url, init);
    };
    renderAt("/incidents");
    expect(await screen.findByText(/no recent incidents/i)).toBeInTheDocument();
  });
});
