import type { components } from "../../lib/api/schema";
import { api, route } from "../../lib/api/client";

export type AdminUserRow = components["schemas"]["AdminUserRow"];
export type AdminUserDetail = components["schemas"]["AdminUserDetail"];
export type AdminRole = components["schemas"]["AdminRole"];
export type AdminRoleCatalog = components["schemas"]["AdminRoleCatalog"];
export type AdminUserStatusResult =
  components["schemas"]["AdminUserStatusResult"];

export interface UsersFilters {
  q?: string;
  status?: "ACTIVE" | "DISABLED";
  role_id?: string;
}

export async function fetchAdminUsers(
  filters: UsersFilters,
  cursor: string | null,
  signal?: AbortSignal,
) {
  const qs = new URLSearchParams();
  qs.set("limit", "50");
  if (filters.q) qs.set("q", filters.q);
  if (filters.status) qs.set("status", filters.status);
  if (filters.role_id) qs.set("role_id", filters.role_id);
  if (cursor) qs.set("cursor", cursor);
  const res = await api("get", `/admin/users?${qs}` as "/admin/users", {
    signal,
  });
  return {
    users: res.data?.users ?? [],
    next_cursor: (res.data?.next_cursor as string | null | undefined) ?? null,
  };
}

export async function fetchAdminUser(id: string, signal?: AbortSignal) {
  const res = await api(
    "get",
    route("/admin/users/{id}", id),
    { signal },
  );
  return res.data ?? null;
}

export async function fetchRoleCatalog(signal?: AbortSignal) {
  const res = await api("get", "/admin/roles", { signal });
  return res.data ?? null;
}

// Privileged mutations: reason is required server-side (1–500); the
// idempotency key is generated once per user intent by the caller and
// kept stable across retries of that same intent.
export async function suspendUser(
  id: string,
  expectedVersion: number,
  reason: string,
  idem: string,
) {
  const res = await api("post", route("/admin/users/{id}/suspend", id), {
    body: { expected_version: expectedVersion, reason },
    idempotencyKey: idem,
  });
  return res.data ?? null;
}

export async function restoreUser(
  id: string,
  expectedVersion: number,
  reason: string,
  idem: string,
) {
  const res = await api("post", route("/admin/users/{id}/restore", id), {
    body: { expected_version: expectedVersion, reason },
    idempotencyKey: idem,
  });
  return res.data ?? null;
}

export async function revokeUserSessions(
  id: string,
  expectedVersion: number,
  reason: string,
  idem: string,
) {
  const res = await api("post", route("/admin/users/{id}/revoke-sessions", id), {
    body: { expected_version: expectedVersion, reason },
    idempotencyKey: idem,
  });
  return res.data ?? null;
}

export async function setUserQuota(
  id: string,
  monitorLimit: number,
  expectedVersion: number,
  reason: string,
  idem: string,
) {
  const res = await api("patch", route("/admin/users/{id}/quota", id), {
    body: {
      monitor_limit: monitorLimit,
      expected_version: expectedVersion,
      reason,
    },
    idempotencyKey: idem,
  });
  return res.data ?? null;
}

export async function assignUserRoles(
  id: string,
  roleIds: string[],
  expectedVersion: number,
  reason: string,
  idem: string,
) {
  const res = await api("put", route("/admin/users/{id}/roles", id), {
    body: {
      role_ids: roleIds,
      expected_version: expectedVersion,
      reason,
    },
    idempotencyKey: idem,
  });
  return res.data ?? null;
}

export async function createRole(
  code: string,
  name: string,
  permissions: string[],
  reason: string,
  idem: string,
) {
  const res = await api("post", "/admin/roles", {
    body: { code, name, permissions, reason },
    idempotencyKey: idem,
  });
  return res.data?.role ?? null;
}

export async function updateRole(
  id: string,
  name: string | undefined,
  permissions: string[],
  expectedVersion: number,
  reason: string,
  idem: string,
) {
  const res = await api("patch", route("/admin/roles/{id}", id), {
    body: {
      name,
      permissions,
      expected_version: expectedVersion,
      reason,
    },
    idempotencyKey: idem,
  });
  return res.data?.role ?? null;
}
