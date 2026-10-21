import type { paths } from "./schema";

type Methods = "get" | "post" | "put" | "patch" | "delete";

// Exact-operation lookup so a mistyped path/method fails at compile
// time, not at the wire.
export type OpResponse<
  P extends keyof paths,
  M extends keyof paths[P] & Methods,
> = paths[P][M] extends { responses: infer R }
  ? {
      [S in keyof R]: `${S & (string | number)}` extends `2${string}`
        ? R[S] extends { content: { "application/json": infer J } }
          ? J
          : never
        : never;
    }[keyof R]
  : never;

export type OpRequest<
  P extends keyof paths,
  M extends keyof paths[P] & Methods,
> = paths[P][M] extends { requestBody: { content: { "application/json": infer B } } }
  ? B
  : undefined;

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public requestId?: string,
    public fields?: Record<string, unknown>,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

// The server issues a fresh uptime_csrf cookie+token pair; we hold the
// header value in memory only — never localStorage.
let csrfHeader: string | null = null;
let csrfInflight: Promise<void> | null = null;

export async function ensureCsrf(signal?: AbortSignal): Promise<void> {
  if (csrfHeader) return;
  csrfInflight ??= fetch("/api/auth/csrf", { credentials: "same-origin", signal })
    .then(async (res) => {
      const body = (await res.json()) as { data?: { csrf_token?: string } };
      if (!res.ok || !body.data?.csrf_token) {
        throw new ApiError(res.status, "CSRF_UNAVAILABLE", "csrf challenge failed");
      }
      csrfHeader = body.data.csrf_token;
    })
    .finally(() => {
      csrfInflight = null;
    });
  return csrfInflight;
}

// Rotate-forced: a 403 CSRF_REJECTED refetches the pair once and retries.
export function resetCsrf(): void {
  csrfHeader = null;
}

interface RequestOptions {
  body?: unknown;
  signal?: AbortSignal;
}

async function raw<T>(
  method: Methods,
  path: string,
  opts: RequestOptions,
): Promise<T> {
  const headers: Record<string, string> = {};
  const mutating = method !== "get";
  if (mutating) {
    headers["X-CSRF-Token"] = csrfHeader ?? "";
    headers["Content-Type"] = "application/json";
  }
  const res = await fetch(`/api${path}`, {
    method: method.toUpperCase(),
    credentials: "same-origin",
    headers,
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
    signal: opts.signal,
  });
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  const json = text ? JSON.parse(text) : undefined;
  if (!res.ok) {
    const err = json?.error ?? {};
    throw new ApiError(
      res.status,
      typeof err.code === "string" ? err.code : `HTTP_${res.status}`,
      typeof err.message === "string" ? err.message : res.statusText,
      typeof json?.request_id === "string" ? json.request_id : undefined,
      err.fields && typeof err.fields === "object" ? err.fields : undefined,
    );
  }
  return json as T;
}

export async function api<
  P extends keyof paths,
  M extends keyof paths[P] & Methods,
>(
  method: M,
  path: P,
  opts: RequestOptions & { body?: OpRequest<P, M> } = {},
): Promise<OpResponse<P, M>> {
  const mutating = method !== "get";
  if (mutating) await ensureCsrf(opts.signal);
  try {
    return await raw<OpResponse<P, M>>(method, path, opts);
  } catch (e) {
    // One CSRF retry: the pair may have been rotated mid-session.
    if (mutating && e instanceof ApiError && e.status === 403 && e.code === "CSRF_REJECTED") {
      resetCsrf();
      await ensureCsrf(opts.signal);
      return raw<OpResponse<P, M>>(method, path, opts);
    }
    throw e;
  }
}

// Path builders keep wildcard segments typed at the call site.
export function route<P extends string>(template: P, id: string): P {
  return template.replace("{id}", encodeURIComponent(id)) as P;
}
