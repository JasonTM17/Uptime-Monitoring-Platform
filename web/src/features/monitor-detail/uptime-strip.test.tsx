import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { makeQueryClient } from "../../app/providers";
import { SessionProvider } from "../auth/session";
import { UptimeStrip } from "./UptimeStrip";

function res(body: unknown, status = 200) {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

let handler: (url: string) => Promise<Response>;
beforeEach(() => {
  vi.stubGlobal("fetch", (input: RequestInfo | URL) =>
    handler(typeof input === "string" ? input : input.toString()),
  );
});
afterEach(() => vi.unstubAllGlobals());

const day = (offset: number) =>
  new Date(Date.now() - offset * 86_400_000)
    .toISOString()
    .replace(/T\d\d/, "T10"); // fixed hour inside that day

const bucket = (offset: number, ok: number, valid: number) => ({
  bucket_start: day(offset),
  valid_samples: valid,
  successes: ok,
  failures: valid - ok,
  excluded_samples: 0,
  sample_uptime: valid ? ok / valid : null,
  avg_duration_ms: 100,
});

const renderStrip = () =>
  render(
    <QueryClientProvider client={makeQueryClient()}>
      <MemoryRouter>
        <SessionProvider>
          <UptimeStrip monitorId="m-1" />
        </SessionProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );

describe("UptimeStrip", () => {
  it("renders 30 cells and aggregates buckets by day", async () => {
    handler = (url) => {
      if (url === "/api/auth/me") return res({ data: { user: null } });
      if (url === "/api/monitors/m-1/stats?window=30d")
        return res({
          data: {
            series: [
              bucket(0, 10, 10), // today, 100%
              bucket(0, 4, 6), // today again — merged into the same cell
              bucket(1, 4, 8), // yesterday, 50%
              bucket(2, 0, 0), // no valid samples
            ],
          },
        });
      return res({}, 404);
    };
    renderStrip();
    const cells = await screen.findAllByRole("listitem");
    expect(cells).toHaveLength(30);
    const titles = cells.map((c) => c.getAttribute("title") ?? "");
    expect(titles.some((t) => t.includes("87.5%"))).toBe(true); // 14/16 today
    expect(titles.some((t) => t.includes("50.0%"))).toBe(true); // yesterday
    expect(titles.filter((t) => t.includes("no evidence")).length).toBe(28);
  });

  it("renders nothing when there is no series evidence", async () => {
    handler = (url) => {
      if (url === "/api/auth/me") return res({ data: { user: null } });
      if (url === "/api/monitors/m-1/stats?window=30d")
        return res({ data: { series: [] } });
      return res({}, 404);
    };
    const { container } = renderStrip();
    await waitFor(() => expect(container).toBeEmptyDOMElement());
  });
});
