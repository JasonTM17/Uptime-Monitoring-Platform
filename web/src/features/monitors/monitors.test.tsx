import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
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

const MON = {
  id: "m-1",
  name: "site",
  target_url: "https://example.com",
  method: "GET",
  interval_seconds: 300,
  timeout_seconds: 5,
  expected_status: 200,
  is_paused: false,
  health: "UP",
  generation: 3,
  next_check_at: "2025-01-01T00:05:00Z",
  last_checked_at: "2025-01-01T00:00:00Z",
  last_response_time_ms: 90,
  last_error_type: null,
  freshness: "fresh",
  created_at: "2025-01-01T00:00:00Z",
  updated_at: "2025-01-01T00:00:00Z",
};

function res(body: unknown, status = 200) {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

type Handler = (url: string, init?: RequestInit) => Promise<Response>;
let handler: Handler;
const calls: { url: string; method: string; body?: string }[] = [];

beforeEach(() => {
  calls.length = 0;
  vi.stubGlobal("fetch", (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    calls.push({
      url,
      method: init?.method ?? "GET",
      body: typeof init?.body === "string" ? init.body : undefined,
    });
    return handler(url, init);
  });
});
afterEach(() => vi.unstubAllGlobals());

const authedMe = () => res({ data: { user: USER, session_expires_at: "t" } });
const csrf = () => res({ data: { csrf_token: "tok" } });
// null = unmatched; helpers return Promises so handlers must check
// for null, not for a 404 status.
const defaults = (url: string) => {
  if (url === "/api/auth/me") return authedMe();
  if (url === "/api/auth/csrf") return csrf();
  if (url === "/api/admin/overview") return res({}, 403);
  if (url === "/api/notification-channels")
    return res({ data: { items: [] } });
  return null;
};

function renderAt(path: string) {
  return render(
    <QueryClientProvider client={makeQueryClient()}>
      <MemoryRouter initialEntries={[path]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("monitor forms", () => {
  it("rejects timeout > interval and bad URL client-side", async () => {
    handler = (url) => defaults(url) ?? res({}, 404);
    renderAt("/monitors");
    const name = await screen.findByLabelText(/^name/i);
    await userEvent.type(name, "x");
    await userEvent.type(screen.getByLabelText(/target url/i), "notaurl");
    await userEvent.clear(screen.getByLabelText(/interval/i));
    await userEvent.type(screen.getByLabelText(/interval/i), "60");
    await userEvent.clear(screen.getByLabelText(/timeout/i));
    await userEvent.type(screen.getByLabelText(/timeout/i), "90");
    await userEvent.click(
      screen.getByRole("button", { name: /create monitor/i }),
    );
    expect(
      await screen.findByText(/valid url/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/timeout must be 1–10s/i),
    ).toBeInTheDocument();
    // nothing hit the wire
    expect(calls.filter((c) => c.method === "POST" && c.url === "/api/monitors")).toHaveLength(0);
  });

  it("maps 422 field errors onto inputs", async () => {
    handler = (url, init) => {
      const base = defaults(url);
      if (base !== null) return base;
      if (url === "/api/monitors" && init?.method === "POST")
        return res(
          {
            error: {
              code: "VALIDATION_ERROR",
              message: "invalid",
              fields: { target_url: "url must be public http/https" },
            },
          },
          422,
        );
      return res({}, 404);
    };
    renderAt("/monitors");
    await userEvent.type(await screen.findByLabelText(/^name/i), "site");
    await userEvent.type(
      screen.getByLabelText(/target url/i),
      "https://internal.lan/x",
    );
    await userEvent.click(
      screen.getByRole("button", { name: /create monitor/i }),
    );
    expect(
      await screen.findByText("url must be public http/https"),
    ).toBeInTheDocument();
  });

  it("shows the safe quota scope on 409 QUOTA_EXCEEDED", async () => {
    handler = (url, init) => {
      const base = defaults(url);
      if (base !== null) return base;
      if (url === "/api/monitors" && init?.method === "POST")
        return res(
          {
            error: {
              code: "QUOTA_EXCEEDED",
              message: "monitor limit reached",
              fields: { scope: "owner_monitor_limit" },
            },
          },
          409,
        );
      return res({}, 404);
    };
    renderAt("/monitors");
    await userEvent.type(await screen.findByLabelText(/^name/i), "site");
    await userEvent.type(
      screen.getByLabelText(/target url/i),
      "https://example.com",
    );
    await userEvent.click(
      screen.getByRole("button", { name: /create monitor/i }),
    );
    expect(
      await screen.findByText(/monitor limit reached \(owner_monitor_limit\)/),
    ).toBeInTheDocument();
  });

  it("generation conflict shows reload banner, never blind overwrite", async () => {
    let patches = 0;
    handler = (url, init) => {
      const base = defaults(url);
      if (base !== null) return base;
      if (url === "/api/monitors/m-1" && init?.method === "GET")
        return res({ data: { ...MON, generation: 3 + patches } });
      if (url === "/api/monitors/m-1" && init?.method === "PATCH") {
        patches++;
        return res(
          {
            error: {
              code: "CONFLICT",
              message: "monitor changed since read",
            },
          },
          409,
        );
      }
      return res({}, 404);
    };
    renderAt("/monitors/m-1");
    await screen.findByText("gen 3");
    await userEvent.click(
      await screen.findByRole("button", { name: /save changes/i }),
    );
    expect(
      await screen.findByText(/changed elsewhere/i),
    ).toBeInTheDocument();
    // only one PATCH went out — no auto retry of a stale write
    expect(calls.filter((c) => c.method === "PATCH")).toHaveLength(1);
  });

  it("pause/resume carry expected_generation; dialog cancels via Escape", async () => {
    const posts: { url: string; body?: string }[] = [];
    handler = (url, init) => {
      const base = defaults(url);
      if (base !== null) return base;
      if (url === "/api/monitors/m-1" && !init?.method?.match(/POST|PATCH|DELETE/))
        return res({ data: MON });
      if (url === "/api/monitors/m-1/pause" && init?.method === "POST") {
        posts.push({ url, body: init.body as string });
        return res({ data: { ...MON, is_paused: true, generation: 4 } });
      }
      return res({}, 404);
    };
    renderAt("/monitors/m-1");
    await userEvent.click(
      await screen.findByRole("button", { name: /^pause$/i }),
    );
    await waitFor(() => expect(posts).toHaveLength(1));
    expect(JSON.parse(posts[0]!.body!)).toEqual({ expected_generation: 3 });

    // Escape closes the delete dialog without a DELETE call
    await userEvent.click(
      screen.getByRole("button", { name: /delete…/i }),
    );
    const dialog = await screen.findByRole("dialog");
    await userEvent.keyboard("{Escape}");
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(dialog).toBeDefined();
    expect(calls.filter((c) => c.method === "DELETE")).toHaveLength(0);
  });

  it("delete sends the generation fence and navigates on success", async () => {
    const dels: { url: string; body?: string }[] = [];
    handler = (url, init) => {
      const base = defaults(url);
      if (base !== null) return base;
      if (url === "/api/monitors/m-1" && init?.method === "DELETE") {
        dels.push({ url, body: init.body as string });
        return Promise.resolve(new Response(null, { status: 204 }));
      }
      if (url === "/api/monitors/m-1") return res({ data: MON });
      if (url === "/api/dashboard/summary")
        return res({ data: { monitors: 0 } });
      if (url.startsWith("/api/monitors?"))
        return res({ data: { items: [], has_more: false, next_cursor: null } });
      return res({}, 404);
    };
    renderAt("/monitors/m-1");
    await userEvent.click(
      await screen.findByRole("button", { name: /delete…/i }),
    );
    const dialog = await screen.findByRole("dialog");
    await userEvent.click(
      within(dialog).getByRole("button", { name: /^delete$/i }),
    );
    await waitFor(() => expect(dels).toHaveLength(1));
    expect(JSON.parse(dels[0]!.body!)).toEqual({ expected_generation: 3 });
    // lands back on the dashboard
    await waitFor(() =>
      expect(
        screen.queryByRole("heading", { name: /site/i }),
      ).not.toBeInTheDocument(),
    );
  });
});
