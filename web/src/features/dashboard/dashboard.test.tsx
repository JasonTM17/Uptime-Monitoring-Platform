import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
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

beforeEach(() => {
  vi.stubGlobal("fetch", (input: RequestInfo | URL, init?: RequestInit) =>
    handler(typeof input === "string" ? input : input.toString(), init),
  );
});
afterEach(() => vi.unstubAllGlobals());

const authedMe = () => res({ data: { user: USER, session_expires_at: "t" } });

function renderApp() {
  return render(
    <QueryClientProvider client={makeQueryClient()}>
      <MemoryRouter initialEntries={["/"]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const monitor = (over: Record<string, unknown>) => ({
  id: "m-1",
  name: "m1",
  target_url: "https://example.com",
  method: "GET",
  interval_seconds: 60,
  timeout_seconds: 5,
  expected_status: 200,
  is_paused: false,
  health: "UP",
  generation: 1,
  next_check_at: "2025-01-01T00:01:00Z",
  last_checked_at: "2025-01-01T00:00:00Z",
  last_response_time_ms: 100,
  last_error_type: null,
  freshness: "fresh",
  created_at: "2025-01-01T00:00:00Z",
  updated_at: "2025-01-01T00:00:00Z",
  ...over,
});

const summary = (over: Record<string, unknown>) => ({
  monitors: 0,
  active: 0,
  paused: 0,
  up: 0,
  down: 0,
  open_incidents: 0,
  sample_uptime_24h: null,
  recent_incidents: [],
  quota: {
    used: 0,
    active: 0,
    paused: 0,
    limit: 10,
    profile: "local",
    as_of: "2025-01-01T00:00:00Z",
    source: "server",
  },
  as_of: "2025-01-01T00:00:00Z",
  ...over,
});

describe("dashboard", () => {
  it("renders honest empty + no-samples states", async () => {
    handler = (url) => {
      if (url === "/api/auth/me") return authedMe();
      if (url === "/api/dashboard/summary")
        return res({ data: summary({}) });
      if (url.startsWith("/api/monitors"))
        return res({ data: { items: [], has_more: false, next_cursor: null } });
      if (url === "/api/admin/overview") return res({}, 403);
      return res({}, 404);
    };
    renderApp();
    expect(await screen.findByText("No samples")).toBeInTheDocument();
    expect(
      await screen.findByText(/no monitors match this view/i),
    ).toBeInTheDocument();
    expect(screen.queryByText("100%")).not.toBeInTheDocument();
  });

  it("shows sampled uptime, paused badges, and stale-without-downgrade", async () => {
    handler = (url) => {
      if (url === "/api/auth/me") return authedMe();
      if (url === "/api/dashboard/summary")
        return res({
          data: summary({
            monitors: 3,
            up: 1,
            paused: 1,
            sample_uptime_24h: 0.9375,
            quota: {
              used: 3,
              active: 2,
              paused: 1,
              limit: 10,
              profile: "local",
              as_of: "2025-01-01T00:00:00Z",
              source: "server",
            },
          }),
        });
      if (url.startsWith("/api/monitors"))
        return res({
          data: {
            items: [
              monitor({ id: "m1", name: "paused-one", is_paused: true }),
              monitor({
                id: "m2",
                name: "stale-one",
                health: "UP",
                freshness: "stale",
              }),
              monitor({
                id: "m3",
                name: "unknown-one",
                health: "UNKNOWN",
                freshness: null,
              }),
            ],
            has_more: false,
            next_cursor: null,
          },
        });
      if (url === "/api/admin/overview") return res({}, 403);
      return res({}, 404);
    };
    renderApp();
    expect(await screen.findByText("93.8%")).toBeInTheDocument();
    expect(await screen.findByText("PAUSED")).toBeInTheDocument();
    // stale evidence keeps the real health — never repainted as DOWN
    expect(await screen.findByText("STALE")).toBeInTheDocument();
    const table = screen.getByRole("table");
    expect(within(table).getByText("UP")).toBeInTheDocument();
    expect(within(table).getByText("UNKNOWN")).toBeInTheDocument();
    expect(within(table).getByText("NO DATA")).toBeInTheDocument();
    // quota from the server projection, not a hardcoded cap
    expect(screen.getByText("3 / 10")).toBeInTheDocument();
    expect(screen.getByText(/local · server/)).toBeInTheDocument();
  });

  it("appends keyset pages via Load more", async () => {
    handler = (url) => {
      if (url === "/api/auth/me") return authedMe();
      if (url === "/api/dashboard/summary") return res({ data: summary({}) });
      if (url === "/api/monitors?limit=20")
        return res({
          data: {
            items: [monitor({ id: "a", name: "page-one" })],
            has_more: true,
            next_cursor: "m1.abc",
          },
        });
      if (url === "/api/monitors?limit=20&cursor=m1.abc")
        return res({
          data: {
            items: [monitor({ id: "b", name: "page-two" })],
            has_more: false,
            next_cursor: null,
          },
        });
      if (url === "/api/admin/overview") return res({}, 403);
      return res({}, 404);
    };
    renderApp();
    await screen.findByText("page-one");
    await userEvent.click(
      await screen.findByRole("button", { name: /load more/i }),
    );
    expect(await screen.findByText("page-two")).toBeInTheDocument();
    expect(screen.getByText("page-one")).toBeInTheDocument();
  });

  it(
    "shows an error panel with retry when the summary fails",
    { timeout: 15000 },
    async () => {
    handler = (url) => {
      if (url === "/api/auth/me") return authedMe();
      if (url === "/api/dashboard/summary")
        return res({ error: { code: "INTERNAL_ERROR", message: "boom" } }, 500);
      if (url.startsWith("/api/monitors"))
        return res({ data: { items: [], has_more: false, next_cursor: null } });
      if (url === "/api/admin/overview") return res({}, 403);
      return res({}, 404);
    };
    renderApp();
    expect(
      await screen.findByText(/load the dashboard summary/i, undefined, {
        timeout: 10000,
      }),
    ).toBeInTheDocument();
    },
  );

  it("filter pills drive query params and rows show latency/method/next", async () => {
    let sawPaused = false;
    const soon = new Date(Date.now() + 45_000).toISOString();
    const recent = new Date(Date.now() - 5_000).toISOString();
    handler = (url) => {
      if (url === "/api/auth/me") return authedMe();
      if (url === "/api/dashboard/summary") return res({ data: summary({}) });
      if (url.startsWith("/api/monitors")) {
        if (new URL(url, "http://x").searchParams.get("paused") === "true")
          sawPaused = true;
        return res({
          data: {
            items: [
              monitor({
                id: "m1",
                name: "row-one",
                last_response_time_ms: 87,
                next_check_at: soon,
                last_checked_at: recent,
              }),
            ],
            has_more: false,
            next_cursor: null,
          },
        });
      }
      if (url === "/api/admin/overview") return res({}, 403);
      return res({}, 404);
    };
    renderApp();
    const table = await screen.findByRole("table");
    // richer row: method chip, latency, relative last check, next-check countdown
    expect(within(table).getByText("GET")).toBeInTheDocument();
    expect(within(table).getByText("87ms")).toBeInTheDocument();
    expect(within(table).getByText(/^[0-9]+s ago$/)).toBeInTheDocument();
    expect(within(table).getByText(/^4[0-9]s$/)).toBeInTheDocument();

    const paused = screen
      .getByRole("group", { name: "Filter by paused" })
      .querySelector("[aria-pressed='true']");
    expect(paused).toHaveTextContent("All");
    await userEvent.click(
      within(
        screen.getByRole("group", { name: "Filter by paused" }),
      ).getByRole("button", { name: "Paused" }),
    );
    await screen.findByText("row-one");
    expect(sawPaused).toBe(true);
    const health = screen.getByRole("group", { name: "Filter by health" });
    await userEvent.click(
      within(health).getByRole("button", { name: "DOWN" }),
    );
    expect(
      within(health).getByRole("button", { name: "DOWN" }),
    ).toHaveAttribute("aria-pressed", "true");
  });
});
