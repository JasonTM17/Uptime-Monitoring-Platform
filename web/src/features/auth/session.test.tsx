import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { makeQueryClient } from "../../app/providers";
import { App } from "../../app/App";

const USER_A = {
  id: "u-a",
  email: "a@example.com",
  display_name: "A",
  status: "ACTIVE",
  created_at: "2025-01-01T00:00:00Z",
};
const USER_B = { ...USER_A, id: "u-b", email: "b@example.com" };

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

// Controllable fetch — tests queue responses per URL.
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

function renderApp(path = "/") {
  const qc = makeQueryClient();
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("auth shell", () => {
  it("fetches a CSRF pair before the first mutating request", async () => {
    handler = (url) => {
      if (url === "/api/auth/csrf")
        return res({ data: { csrf_token: "tok-1" } });
      if (url === "/api/auth/login")
        return res({ data: { user: USER_A, session_expires_at: "t" } });
      if (url === "/api/auth/me") return res({ data: null }, 401);
      return res({}, 404);
    };
    renderApp("/login");
    await userEvent.type(await screen.findByLabelText(/email/i), "a@example.com");
    await userEvent.type(screen.getByLabelText(/password/i), "twelve-chars!!");
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));

    await waitFor(() =>
      expect(calls.some((c) => c.url === "/api/auth/login")).toBe(true),
    );
    const csrfIdx = calls.findIndex((c) => c.url === "/api/auth/csrf");
    const loginIdx = calls.findIndex((c) => c.url === "/api/auth/login");
    expect(csrfIdx).toBeGreaterThanOrEqual(0);
    expect(csrfIdx).toBeLessThan(loginIdx);
    const loginCall = calls[loginIdx];
    expect(
      (loginCall?.init?.headers as Record<string, string>)["X-CSRF-Token"],
    ).toBe("tok-1");
    expect(localStorage.length).toBe(0);
  });

  it("shows the generic server message on invalid credentials", async () => {
    handler = (url) => {
      if (url === "/api/auth/csrf") return res({ data: { csrf_token: "t" } });
      if (url === "/api/auth/login")
        return res(
          { error: { code: "UNAUTHENTICATED", message: "invalid credentials" } },
          401,
        );
      if (url === "/api/auth/me") return res({ data: null }, 401);
      return res({}, 404);
    };
    renderApp("/login");
    await userEvent.type(await screen.findByLabelText(/email/i), "a@example.com");
    await userEvent.type(screen.getByLabelText(/password/i), "wrong-password");
    await userEvent.click(screen.getByRole("button", { name: /sign in/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "invalid credentials",
    );
  });

  it("a stale identity response cannot hydrate a new login", async () => {
    // Cache-level proof: an in-flight /me issued under the old identity
    // is destroyed by clear(); its late resolution cannot overwrite the
    // new identity the login wrote.
    const qc = makeQueryClient();
    let resolveStale: (v: { data: unknown }) => void = () => {};
    const stalePromise = new Promise<{ data: unknown }>((r) => {
      resolveStale = r;
    });
    const inflight = qc.fetchQuery<{ data: unknown } | null>({
      queryKey: ["me"],
      queryFn: () => stalePromise,
    });

    // The new identity lands first (what login onSuccess does).
    qc.clear();
    qc.setQueryData(["me"], { user: USER_B, session_expires_at: "t2" });

    resolveStale({ data: { user: USER_A, session_expires_at: "t1" } });
    await inflight.catch(() => undefined);

    expect(qc.getQueryData(["me"])).toEqual({
      user: USER_B,
      session_expires_at: "t2",
    });
  });

  it("still ends the local session when logout's request fails", async () => {
    handler = (url) => {
      if (url === "/api/auth/me")
        return res({ data: { user: USER_A, session_expires_at: "t" } });
      if (url === "/api/auth/csrf") return res({ data: { csrf_token: "t" } });
      if (url === "/api/auth/logout") return Promise.reject(new TypeError("offline"));
      if (url === "/api/admin/overview") return res({}, 403);
      return res({}, 404);
    };
    renderApp("/");
    await screen.findByText("a@example.com");
    await userEvent.click(screen.getByRole("button", { name: /sign out/i }));
    await waitFor(() =>
      expect(screen.queryByText("a@example.com")).not.toBeInTheDocument(),
    );
    expect(
      await screen.findByRole("heading", { name: /sign in/i }),
    ).toBeInTheDocument();
  });

  it("hides admin nav and denies a direct admin URL without a grant", async () => {
    handler = (url) => {
      if (url === "/api/auth/me")
        return res({ data: { user: USER_A, session_expires_at: "t" } });
      if (url === "/api/admin/overview") return res({}, 403);
      return res({}, 404);
    };
    renderApp("/admin");
    expect(
      await screen.findByRole("heading", { name: /access denied/i }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("navigation", { name: "Administration" }),
    ).not.toBeInTheDocument();
  });

  it("stores no token in web storage", async () => {
    handler = (url) => {
      if (url === "/api/auth/csrf") return res({ data: { csrf_token: "t" } });
      if (url === "/api/auth/me")
        return res({ data: { user: USER_A, session_expires_at: "t" } });
      if (url === "/api/admin/overview") return res({}, 403);
      return res({}, 404);
    };
    renderApp("/");
    await screen.findByText("a@example.com");
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });
});
