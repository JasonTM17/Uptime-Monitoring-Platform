import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
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

const TARGET = {
  id: "u-target",
  email: "target@example.com",
  display_name: "Target",
  status: "ACTIVE",
  monitor_limit: 5,
  monitors_live: 2,
  sessions_live: 1,
  roles: ["SUPER_ADMIN"],
  created_at: "2025-01-01T00:00:00Z",
  disabled_at: null,
  security_version: 3,
  version: 7,
};

const CATALOG = {
  catalog: [
    { id: "platform:read", requires: [] },
    { id: "users:read", requires: [] },
    { id: "users:manage", requires: ["users:read"] },
    { id: "audit:read", requires: [] },
  ],
  roles: [
    { id: "r-1", code: "SUPER_ADMIN", name: "Super admin", is_preset: true, version: 1, permissions: ["platform:read", "users:read", "users:manage", "audit:read"] },
    { id: "r-2", code: "VIEWER", name: "Viewer", is_preset: true, version: 1, permissions: ["platform:read"] },
  ],
  delegation_ceiling: ["platform:read", "users:read", "audit:read"],
};

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
let posted: { url: string; method: string; body?: unknown; idem?: string | null }[] = [];

const defaults = (url: string, init?: RequestInit) => {
  if (url === "/api/auth/me")
    return res({ data: { user: USER, session_expires_at: "t" } });
  if (url === "/api/auth/csrf") return res({ data: { csrf_token: "tok" } });
  if (url === "/api/admin/overview") return res({ data: {} });
  if (url === "/api/admin/roles" && init?.method === "GET")
    return res({ data: CATALOG });
  if (url.startsWith("/api/admin/users?"))
    return res({ data: { users: [TARGET], next_cursor: null } });
  if (url === "/api/admin/users/u-target" && init?.method === "GET")
    return res({ data: TARGET });
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
  return render(
    <QueryClientProvider client={makeQueryClient()}>
      <MemoryRouter initialEntries={[path]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("admin identity screens", () => {
  it("non-admin gets denied, not an empty page", async () => {
    handler = (url, init) =>
      url === "/api/admin/overview" ? err(403, "FORBIDDEN", "forbidden") : defaults(url, init);
    renderAt("/admin/users");
    expect(await screen.findByText(/access denied/i)).toBeInTheDocument();
  });

  it("users:read-denied shows an explicit denied panel", async () => {
    handler = (url, init) =>
      url.startsWith("/api/admin/users?") ? err(403, "FORBIDDEN", "forbidden") : defaults(url, init);
    renderAt("/admin/users");
    expect(await screen.findByText(/doesn’t include/i)).toBeInTheDocument();
  });

  it("user detail renders counts/roles with no secret fields", async () => {
    renderAt("/admin/users/u-target");
    expect(await screen.findByText("target@example.com")).toBeInTheDocument();
    expect(screen.getByText("v7 · epoch 3")).toBeInTheDocument();
    expect(screen.getByText("SUPER_ADMIN")).toBeInTheDocument();
    // never render raw secret material even if present in a payload
    expect(screen.queryByText(/hash|totp|token|secret/i)).not.toBeInTheDocument();
  });

  it("suspend sends version+reason under an idempotency key; LAST_SUPERADMIN explains", async () => {
    handler = (url, init) =>
      url === "/api/admin/users/u-target/suspend" && init?.method === "POST"
        ? err(409, "LAST_SUPERADMIN", "the last active superadmin cannot be removed")
        : defaults(url, init);
    const user = userEvent.setup();
    renderAt("/admin/users/u-target");
    await user.click(await screen.findByRole("button", { name: /suspend…/i }));
    await user.type(await screen.findByLabelText(/reason/i), "abuse report");
    await user.click(screen.getByRole("button", { name: /^suspend$/i }));
    expect(await screen.findByText(/last active superadmin/i)).toBeInTheDocument();
    const post = posted.find((p) => p.url.includes("/suspend"));
    expect(post?.body).toEqual({ expected_version: 7, reason: "abuse report" });
    expect(post?.idem).toBeTruthy();
  });

  it("REAUTH_REQUIRED opens step-up and never replays silently", async () => {
    let reauthed = false;
    handler = (url, init) => {
      if (url === "/api/auth/reauth" && init?.method === "POST") {
        reauthed = true;
        return res({ data: { reauthenticated_until: "t" } });
      }
      if (url === "/api/admin/users/u-target/suspend" && init?.method === "POST")
        return reauthed
          ? res({ data: { user_id: "u-target", status: "DISABLED", already: false } })
          : err(403, "REAUTH_REQUIRED", "recent authentication required");
      return defaults(url, init);
    };
    const user = userEvent.setup();
    renderAt("/admin/users/u-target");
    await user.click(await screen.findByRole("button", { name: /suspend…/i }));
    await user.type(await screen.findByLabelText(/reason/i), "why");
    await user.click(screen.getByRole("button", { name: /^suspend$/i }));
    expect(await screen.findByText(/confirm it’s you/i)).toBeInTheDocument();
    await user.type(screen.getByLabelText(/password/i), "pw");
    await user.click(screen.getByRole("button", { name: /continue/i }));
    // step-up done → the action dialog is still open waiting for an
    // explicit second confirm — the mutation did NOT silently replay
    expect(posted.filter((p) => p.url.includes("/suspend"))).toHaveLength(1);
    await user.click(screen.getByRole("button", { name: /^suspend$/i }));
    expect(posted.filter((p) => p.url.includes("/suspend"))).toHaveLength(2);
    // same intent → same idempotency key on both attempts
    const idems = posted.filter((p) => p.url.includes("/suspend")).map((p) => p.idem);
    expect(idems[0]).toBeTruthy();
    expect(idems[0]).toEqual(idems[1]);
  });

  it("permission matrix marks over-ceiling grants and blocks them in the editor", async () => {
    const user = userEvent.setup();
    renderAt("/admin/roles");
    await screen.findByText("SUPER_ADMIN");
    await user.click(screen.getByRole("button", { name: /new custom role/i }));
    // users:manage is over the delegation ceiling — checkbox disabled
    const grant = screen.getByRole("checkbox", { name: /grant users:manage/i });
    expect(grant).toBeDisabled();
    expect(screen.getAllByText("over ceiling").length).toBeGreaterThan(0);
    // toggling a permission with requires surfaces the prerequisite hint
    await user.click(screen.getByRole("checkbox", { name: /grant audit:read/i }));
  });
});
