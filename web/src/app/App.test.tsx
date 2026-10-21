import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { makeQueryClient } from "./providers";
import { App } from "./App";

const anonymous = Promise.resolve(
  new Response(JSON.stringify({ data: null }), {
    status: 401,
    headers: { "Content-Type": "application/json" },
  }),
);

beforeEach(() => {
  vi.stubGlobal("fetch", () => anonymous);
});

function renderAt(path: string) {
  return render(
    <QueryClientProvider client={makeQueryClient()}>
      <MemoryRouter initialEntries={[path]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("app shell", () => {
  it("redirects an anonymous visitor at / to sign-in", async () => {
    renderAt("/");
    expect(
      await screen.findByRole("heading", { name: "Sign in" }),
    ).toBeInTheDocument();
  });

  it("renders a semantic fallback for unknown routes", async () => {
    renderAt("/definitely-not-a-route");
    expect(
      await screen.findByRole("heading", { name: "Page not found" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("alert")).toBeInTheDocument();
  });
});
