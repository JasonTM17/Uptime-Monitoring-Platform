import type { components } from "../../lib/api/schema";
import { api, route } from "../../lib/api/client";

export type SessionDTO = components["schemas"]["SessionDTO"];

export interface SessionsPage {
  sessions: SessionDTO[];
  page: number;
  page_size: number;
}

export async function fetchSessions(
  page: number,
  signal?: AbortSignal,
): Promise<SessionsPage> {
  const res = await api("get", `/auth/sessions?page=${page}` as "/auth/sessions", {
    signal,
  });
  const d = res.data;
  return {
    sessions: d?.sessions ?? [],
    page: d?.page ?? page,
    page_size: d?.page_size ?? 20,
  };
}

export async function revokeSession(id: string): Promise<void> {
  await api("delete", route("/auth/sessions/{id}", id));
}

// Requires recent-auth; on 403 REAUTH_REQUIRED the caller runs the
// step-up dialog and retries once. Revokes every session including
// this one — the next identity read ends the local session.
export async function revokeAllSessions(): Promise<number> {
  const res = await api("post", "/auth/sessions/revoke-all");
  return (res.data?.revoked_count as number | undefined) ?? 0;
}
