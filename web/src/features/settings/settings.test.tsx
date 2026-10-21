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

const CUR = {
  id: "s-cur",
  device_label: "this laptop",
  created_at: "2025-01-01T00:00:00Z",
  last_seen_at: "2025-01-02T00:00:00Z",
  expires_at: "2025-01-10T00:00:00Z",
  current: true,
};
const OTHER = {
  id: "s-other",
  device_label: "phone",
  created_at: "2025-01-01T00:00:00Z",
  last_seen_at: "2025-01-01T12:00:00Z",
  expires_at: "2025-01-08T00:00:00Z",
  current: false,
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
  res({ error: { code, message }, request_id: "r" }, status);

type Handler = (url: string, init?: RequestInit) => Promise<Response> | null;
let handler: Handler;
let meAuthed = true;

const defaults = (url: string) => {
  if (url === "/api/auth/me")
    return meAuthed
      ? res({ data: { user: USER, session_expires_at: "t" } })
      : res({ error: { code: "UNAUTHENTICATED", message: "expired" }, request_id: "r" }, 401);
  if (url === "/api/admin/overview") return res({}, 403);
  if (url === "/api/auth/csrf") return res({ data: { csrf_token: "tok" } });
  if (url === "/api/dashboard/summary")
    return res({
      data: {
        monitors: 3, active: 2, paused: 1, up: 2, down: 0,
        open_incidents: 0, sample_uptime_24h: 1, recent_incidents: [],
        quota: { used: 3, active: 2, paused: 1, limit: 7, profile: "hosted-free", as_of: "t", source: "server" },
        as_of: "t",
      },
    });
  if (url === "/api/auth/sessions?page=1" || url === "/api/auth/sessions")
    return res({ data: { sessions: [CUR, OTHER], page: 1, page_size: 20 } });
  return null;
};

let deleted: string[] = [];
let posted: string[] = [];
beforeEach(() => {
  deleted = [];
  posted = [];
  meAuthed = true;
  handler = (url) => defaults(url);
  vi.stubGlobal("fetch", (i: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof i === "string" ? i : i.toString();
    if (init?.method === "DELETE") deleted.push(url);
    if (init?.method === "POST") posted.push(url);
    const r = handler(url, init);
    return r === null ? res({}, 404) : r;
  });
});
afterEach(() => vi.unstubAllGlobals());

function renderSettings() {
  return render(
    <QueryClientProvider client={makeQueryClient()}>
      <MemoryRouter initialEntries={["/settings"]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("settings sessions", () => {
  it("lists sessions with the current one marked, plus profile readback", async () => {
    renderSettings();
    expect(await screen.findByText("this laptop")).toBeInTheDocument();
    expect(screen.getByText("this session")).toBeInTheDocument();
    expect(screen.getByText("phone")).toBeInTheDocument();
    // profile readback: identity from /me + quota from dashboard summary
    expect(screen.getAllByText("u@example.com").length).toBeGreaterThan(0);
    expect(await screen.findByText("3 / 7 (hosted-free)")).toBeInTheDocument();
    // honest MFA state — no fake toggle
    expect(screen.getByText(/isn’t offered/i)).toBeInTheDocument();
  });

  it("revoke other session deletes by id; foreign 404 is honest", async () => {
    handler = (url, init) => {
      if (init?.method === "DELETE" && url === "/api/auth/sessions/s-other")
        return err(404, "NOT_FOUND", "session not found");
      return defaults(url);
    };
    const user = userEvent.setup();
    renderSettings();
    const phone = await screen.findByText("phone");
    await user.click(
      phone.closest("li")!.querySelector("button")! as HTMLElement,
    );
    expect(deleted).toContain("/api/auth/sessions/s-other");
    expect(await screen.findByText(/already gone/i)).toBeInTheDocument();
  });

  it("revoking the current session ends the app session (login redirect)", async () => {
    handler = (url, init) => {
      if (init?.method === "DELETE" && url === "/api/auth/sessions/s-cur") {
        meAuthed = false; // server revokes; next /me is 401
        return Promise.resolve(new Response(null, { status: 204 }));
      }
      return defaults(url);
    };
    const user = userEvent.setup();
    renderSettings();
    const cur = await screen.findByText("this laptop");
    await user.click(
      cur.closest("li")!.querySelector("button")! as HTMLElement,
    );
    expect(deleted).toContain("/api/auth/sessions/s-cur");
    // identity re-read 401s → session provider drops to anonymous →
    // the guard lands on the login screen
    expect(
      await screen.findByRole("button", { name: /sign in/i }, { timeout: 4000 }),
    ).toBeInTheDocument();
  });

  it("revoke-all runs step-up then explicit confirm, then drops to login", async () => {
    let reauthed = false;
    handler = (url, init) => {
      if (url === "/api/auth/reauth" && init?.method === "POST") {
        reauthed = true;
        return res({ data: { reauthenticated_until: "t" } });
      }
      if (url === "/api/auth/sessions/revoke-all" && init?.method === "POST") {
        if (!reauthed) return err(403, "REAUTH_REQUIRED", "recent authentication required");
        meAuthed = false;
        return res({ data: { revoked_count: 3 } });
      }
      return defaults(url);
    };
    const user = userEvent.setup();
    renderSettings();
    await user.click(
      await screen.findByRole("button", { name: /sign out everywhere/i }),
    );
    // confirm dialog appears; confirm it → server demands reauth
    await user.click(
      await screen.findByRole("button", { name: /^sign out everywhere$/i }),
    );
    expect(await screen.findByText(/confirm it’s you/i)).toBeInTheDocument();
    // step-up succeeds → confirm dialog reappears (no silent replay)
    await user.type(screen.getByLabelText(/password/i), "pw");
    await user.click(screen.getByRole("button", { name: /continue/i }));
    const confirmBtn = await screen.findByRole("button", {
      name: /^sign out everywhere$/i,
    });
    await user.click(confirmBtn);
    expect(posted).toContain("/api/auth/sessions/revoke-all");
    expect(
      await screen.findByRole("button", { name: /sign in/i }, { timeout: 4000 }),
    ).toBeInTheDocument();
  });

  it("cancelling the reauth dialog performs no action", async () => {
    handler = (url, init) => {
      if (url === "/api/auth/sessions/revoke-all" && init?.method === "POST")
        return err(403, "REAUTH_REQUIRED", "recent authentication required");
      return defaults(url);
    };
    const user = userEvent.setup();
    renderSettings();
    await user.click(
      await screen.findByRole("button", { name: /sign out everywhere/i }),
    );
    await user.click(
      await screen.findByRole("button", { name: /^sign out everywhere$/i }),
    );
    await screen.findByText(/confirm it’s you/i);
    await user.click(screen.getByRole("button", { name: /cancel/i }));
    // cancel → no reauth POST, no second revoke-all POST
    expect(posted).not.toContain("/api/auth/reauth");
    expect(
      posted.filter((u) => u === "/api/auth/sessions/revoke-all"),
    ).toHaveLength(1);
  });

  it("wrong password gets a generic failure, input cleared", async () => {
    handler = (url, init) => {
      if (url === "/api/auth/sessions/revoke-all" && init?.method === "POST")
        return err(403, "REAUTH_REQUIRED", "recent authentication required");
      if (url === "/api/auth/reauth" && init?.method === "POST")
        return err(401, "UNAUTHENTICATED", "invalid credentials");
      return defaults(url);
    };
    const user = userEvent.setup();
    renderSettings();
    await user.click(
      await screen.findByRole("button", { name: /sign out everywhere/i }),
    );
    await user.click(
      await screen.findByRole("button", { name: /^sign out everywhere$/i }),
    );
    const pw = await screen.findByLabelText(/password/i);
    await user.type(pw, "wrong");
    await user.click(screen.getByRole("button", { name: /continue/i }));
    // uniform failure — never "wrong password for THIS account" detail
    expect(
      await screen.findByText(/password verification failed/i),
    ).toBeInTheDocument();
    expect((pw as HTMLInputElement).value).toBe("");
    // the failed reauth never retries the destructive call
    expect(
      posted.filter((u) => u === "/api/auth/sessions/revoke-all"),
    ).toHaveLength(1);
  });

  it("escape closes the confirm dialog without revoking", async () => {
    const user = userEvent.setup();
    renderSettings();
    await user.click(
      await screen.findByRole("button", { name: /sign out everywhere/i }),
    );
    expect(await screen.findByText(/sign out everywhere\?/i)).toBeInTheDocument();
    await user.keyboard("{Escape}");
    expect(
      screen.queryByRole("button", { name: /^sign out everywhere$/i }),
    ).not.toBeInTheDocument();
    expect(posted).not.toContain("/api/auth/sessions/revoke-all");
  });
});
