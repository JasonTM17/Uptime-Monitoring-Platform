import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { makeQueryClient } from "../../app/providers";
import { App } from "../../app/App";

interface Call { url: string; init?: RequestInit }
const calls: Call[] = [];

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
  calls.length = 0;
  localStorage.clear();
  vi.stubGlobal("fetch", (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    calls.push({ url, init });
    return handler(url, init);
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function renderApp(path = "/register") {
  const qc = makeQueryClient();
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

async function fillAndSubmit(email = "new@example.com") {
  await userEvent.type(await screen.findByLabelText(/email/i), email);
  await userEvent.type(screen.getByLabelText(/display name/i), "New User");
  await userEvent.type(screen.getByLabelText(/password/i), "twelve-chars!!");
  await userEvent.click(
    screen.getByRole("button", { name: /create account/i }),
  );
}

describe("register page", () => {
  it("registers with CSRF then lands on sign-in", async () => {
    handler = (url) => {
      if (url === "/api/auth/csrf") return res({ data: { csrf_token: "tok-9" } });
      if (url === "/api/auth/register") return res({ data: { id: "u-1" } }, 201);
      if (url === "/api/auth/me") return res({ data: null }, 401);
      return res({}, 404);
    };
    renderApp();
    await fillAndSubmit();

    await waitFor(() =>
      expect(calls.some((c) => c.url === "/api/auth/register")).toBe(true),
    );
    const reg = calls.find((c) => c.url === "/api/auth/register");
    expect(
      (reg?.init?.headers as Record<string, string>)["X-CSRF-Token"],
    ).toBe("tok-9");
    const body = JSON.parse(reg?.init?.body as string) as Record<string, unknown>;
    expect(body["email"]).toBe("new@example.com");
    expect(body["display_name"]).toBe("New User");
    // Success navigates to /login — the sign-in form appears.
    expect(
      await screen.findByRole("button", { name: /sign in/i }),
    ).toBeInTheDocument();
  });

  it("omits display_name when left blank", async () => {
    handler = (url) => {
      if (url === "/api/auth/csrf") return res({ data: { csrf_token: "t" } });
      if (url === "/api/auth/register") return res({ data: { id: "u-1" } }, 201);
      if (url === "/api/auth/me") return res({ data: null }, 401);
      return res({}, 404);
    };
    renderApp();
    await userEvent.type(await screen.findByLabelText(/email/i), "n@example.com");
    await userEvent.type(screen.getByLabelText(/password/i), "twelve-chars!!");
    await userEvent.click(
      screen.getByRole("button", { name: /create account/i }),
    );
    await waitFor(() =>
      expect(calls.some((c) => c.url === "/api/auth/register")).toBe(true),
    );
    const reg = calls.find((c) => c.url === "/api/auth/register");
    const body = JSON.parse(reg?.init?.body as string) as Record<string, unknown>;
    expect("display_name" in body).toBe(false);
  });

  it("maps 422 field errors onto the alert", async () => {
    handler = (url) => {
      if (url === "/api/auth/csrf") return res({ data: { csrf_token: "t" } });
      if (url === "/api/auth/register")
        return res(
          {
            error: {
              code: "VALIDATION_ERROR",
              message: "validation failed",
              fields: { password: "too short" },
            },
          },
          422,
        );
      if (url === "/api/auth/me") return res({ data: null }, 401);
      return res({}, 404);
    };
    renderApp();
    await fillAndSubmit();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "too short",
    );
    // Still on the register page — no navigation on failure.
    expect(
      screen.getByRole("button", { name: /create account/i }),
    ).toBeInTheDocument();
  });

  it("shows the server message on a vague 409 (anti-enumeration)", async () => {
    handler = (url) => {
      if (url === "/api/auth/csrf") return res({ data: { csrf_token: "t" } });
      if (url === "/api/auth/register")
        return res(
          { error: { code: "CONFLICT", message: "registration unavailable" } },
          409,
        );
      if (url === "/api/auth/me") return res({ data: null }, 401);
      return res({}, 404);
    };
    renderApp();
    await fillAndSubmit();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "registration unavailable",
    );
  });
});
