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

const stats = (over: Record<string, unknown>) => ({
  window_start: "2025-01-01T00:00:00Z",
  window_end: "2025-01-02T00:00:00Z",
  data_start: "2025-01-01T06:00:00Z",
  data_end: "2025-01-02T00:00:00Z",
  valid_samples: 3,
  successes: 2,
  failures: 1,
  excluded_samples: 0,
  expected_samples: 5,
  missed_samples: 2,
  pending_samples: 0,
  coverage: 0.6,
  sample_uptime: 0.666666,
  avg_duration_ms: 120,
  raw_retention_hours: 12,
  hourly_retention_days: 30,
  raw_available_from: "2025-01-01T12:00:00Z",
  resolution: "mixed",
  is_partial: true,
  series: [
    { bucket_start: "2025-01-01T06:00:00Z", valid_samples: 2, successes: 2, failures: 0, excluded_samples: 0, sample_uptime: 1, avg_duration_ms: 100 },
    { bucket_start: "2025-01-01T07:00:00Z", valid_samples: 0, successes: 0, failures: 0, excluded_samples: 0, sample_uptime: null, avg_duration_ms: null },
    { bucket_start: "2025-01-01T08:00:00Z", valid_samples: 1, successes: 0, failures: 1, excluded_samples: 0, sample_uptime: 0, avg_duration_ms: 140 },
  ],
  ...over,
});

const defaults = (url: string) => {
  if (url === "/api/auth/me")
    return res({ data: { user: USER, session_expires_at: "t" } });
  if (url === "/api/admin/overview") return res({}, 403);
  if (url === "/api/notification-channels") return res({ data: { items: [] } });
  if (url === "/api/monitors/m-1") return res({ data: MON });
  if (url === "/api/monitors/m-1/stats?window=24h")
    return res({ data: stats({}) });
  if (url === "/api/monitors/m-1/stats?window=30d")
    return res({ data: stats({ resolution: "hourly" }) });
  if (url.startsWith("/api/monitors/m-1/incidents"))
    return res({ data: { incidents: [], page: { has_more: false } } });
  if (url.startsWith("/api/monitors/m-1/checks"))
    return res({ data: { checks: [], page: { has_more: false } } });
  return null;
};

beforeEach(() => {
  vi.stubGlobal("fetch", (i: RequestInfo | URL, init?: RequestInit) =>
    handler(typeof i === "string" ? i : i.toString(), init),
  );
});
afterEach(() => vi.unstubAllGlobals());

function renderDetail() {
  handler = (url) => defaults(url) ?? res({}, 404);
  return render(
    <QueryClientProvider client={makeQueryClient()}>
      <MemoryRouter initialEntries={["/monitors/m-1"]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("monitor detail statistics", () => {
  it("separates requested vs represented bounds and shows partial", async () => {
    renderDetail();
    expect(await screen.findByText(/requested/)).toBeInTheDocument();
    expect(screen.getByText(/represented/)).toBeInTheDocument();
    expect(screen.getByText("partial window")).toBeInTheDocument();
    expect(screen.getByText("resolution mixed")).toBeInTheDocument();
    // hand-computed fixture: 2/3 valid → 66.7%
    expect(screen.getByText("66.7%")).toBeInTheDocument();
    expect(screen.getByText("60.0%")).toBeInTheDocument();
    expect(screen.getByText(/retained for 12h/)).toBeInTheDocument();
  });

  it("renders an explicit gap bucket instead of bridging nulls", async () => {
    renderDetail();
    await screen.findByText(/requested/);
    // the empty 07:00 bucket exists in the data table as a gap, not a zero success
    const details = await screen.findByText(/data table/i);
    await userEvent.click(details);
    const table = screen.getAllByRole("table").pop()!;
    expect(
      within(table).getByText("2025-01-01T07:00:00Z"),
    ).toBeInTheDocument();
    // its uptime cell is "No evidence" — never fabricated 0% or 100%
    const row = within(table)
      .getByText("2025-01-01T07:00:00Z")
      .closest("tr")!;
    expect(within(row).getByText("No evidence")).toBeInTheDocument();
  });

  it("labels null ratios as no evidence for a new monitor", async () => {
    handler = (url) => {
      const base = defaults(url);
      if (base !== null) {
        if (url === "/api/monitors/m-1/stats?window=24h")
          return res({
            data: stats({
              valid_samples: 0,
              successes: 0,
              failures: 0,
              expected_samples: 0,
              missed_samples: 0,
              coverage: null,
              sample_uptime: null,
              avg_duration_ms: null,
              series: [],
              is_partial: false,
              data_start: null,
              data_end: null,
              resolution: "none",
            }),
          });
        return base;
      }
      return res({}, 404);
    };
    render(
      <QueryClientProvider client={makeQueryClient()}>
        <MemoryRouter initialEntries={["/monitors/m-1"]}>
          <App />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    const cells = await screen.findAllByText("No evidence");
    expect(cells.length).toBeGreaterThanOrEqual(2);
    expect(
      screen.getByText(/no samples in this window yet/i),
    ).toBeInTheDocument();
    expect(screen.queryByText("100%")).not.toBeInTheDocument();
  });

  it("preserves run order and null outcome fields in the checks table", async () => {
    handler = (url) => {
      if (url.startsWith("/api/monitors/m-1/checks"))
        return res({
          data: {
            checks: [
              { run_id: "r2", slot_at: "s2", started_at: null, finished_at: null, status: "COMPLETED", outcome: "SUCCESS", eligible: true, success: true, http_status: 200, duration_ms: 42, observed_at: "o2" },
              { run_id: "r1", slot_at: "s1", started_at: null, finished_at: null, status: "STALE", outcome: null, eligible: null, success: null, http_status: null, duration_ms: null, observed_at: null },
            ],
            page: { has_more: false },
          },
        });
      return defaults(url) ?? res({}, 404);
    };
    render(
      <QueryClientProvider client={makeQueryClient()}>
        <MemoryRouter initialEntries={["/monitors/m-1"]}>
          <App />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    // r2 (newest) renders above r1; server order is authoritative
    const r2 = await screen.findByText("s2");
    const r1 = await screen.findByText("s1");
    expect(r2.compareDocumentPosition(r1)).toBe(
      Node.DOCUMENT_POSITION_FOLLOWING,
    );
    expect(screen.getByText("STALE")).toBeInTheDocument();
  });
});
