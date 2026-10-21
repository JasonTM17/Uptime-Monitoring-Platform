import type { components } from "../../lib/api/schema";
import { api, ApiError } from "../../lib/api/client";

export type User = components["schemas"]["User"];

export interface MeData {
  user: User;
  session_expires_at: string;
}

// 401 → anonymous is a state, not an error. Every other failure stays
// an error so the caller can distinguish "signed out" from "unknown".
export async function fetchMe(signal?: AbortSignal): Promise<MeData | null> {
  try {
    const res = await api("get", "/auth/me", { signal });
    return res.data ?? null;
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) return null;
    throw e;
  }
}

// Capability probe — the contract exposes no permission list on /me,
// so the shell tests the lightest admin read once. 403 means "no
// admin visibility"; the server stays authoritative per route.
export async function probeAdmin(signal?: AbortSignal): Promise<boolean> {
  try {
    await api("get", "/admin/overview", { signal });
    return true;
  } catch (e) {
    if (e instanceof ApiError && (e.status === 401 || e.status === 403)) return false;
    throw e;
  }
}

export function login(input: components["schemas"]["LoginInput"]) {
  return api("post", "/auth/login", { body: input });
}

export function register(input: components["schemas"]["RegisterInput"]) {
  return api("post", "/auth/register", { body: input });
}

export function logout() {
  return api("post", "/auth/logout");
}
