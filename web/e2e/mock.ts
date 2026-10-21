import type { Page } from "@playwright/test";

export function mockApi(page: Page, channels: unknown[] = []) {
  const json = (body: unknown, status = 200) => ({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
  return page.route(
    (url) => url.pathname.startsWith("/api/"),
    (route) => {
      const p = new URL(route.request().url()).pathname;
      const m = route.request().method();
      if (p === "/api/auth/me")
        return route.fulfill(
          json({
            data: {
              user: { id: "u1", email: "u@example.com", display_name: "U", status: "ACTIVE", created_at: "t" },
              session_expires_at: "t",
            },
          }),
        );
      if (p === "/api/auth/csrf")
        return route.fulfill(json({ data: { csrf_token: "tok" } }));
      if (p === "/api/admin/overview") return route.fulfill(json({}, 403));
      if (p === "/api/notification-channels" && m === "GET")
        return route.fulfill(json({ data: { items: channels } }));
      return route.fulfill(json({}, 404));
    },
  );
}
