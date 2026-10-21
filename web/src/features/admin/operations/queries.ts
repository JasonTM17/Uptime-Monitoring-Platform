import type { components } from "../../../lib/api/schema";
import { api, route } from "../../../lib/api/client";

export type AdminOperations = components["schemas"]["AdminOperations"];
export type AdminOverview = components["schemas"]["AdminOverview"];
export type AdminMonitorRow = components["schemas"]["AdminMonitorRow"];
export type AdminOutboxRow = components["schemas"]["AdminOutboxRow"];
export type AdminAuditRow = components["schemas"]["AdminAuditRow"];

export async function fetchOverview(signal?: AbortSignal) {
  const res = await api("get", "/admin/overview", { signal });
  return res.data ?? null;
}

export async function fetchOperations(signal?: AbortSignal) {
  const res = await api("get", "/admin/operations", { signal });
  return res.data ?? null;
}

export interface MonitorFilters {
  owner_id?: string;
  paused?: "true" | "false";
  health?: "UP" | "DOWN" | "UNKNOWN";
}

export async function fetchGlobalMonitors(
  filters: MonitorFilters,
  cursor: string | null,
  signal?: AbortSignal,
) {
  const qs = new URLSearchParams();
  qs.set("limit", "50");
  if (filters.owner_id) qs.set("owner_id", filters.owner_id);
  if (filters.paused) qs.set("paused", filters.paused);
  if (filters.health) qs.set("health", filters.health);
  if (cursor) qs.set("cursor", cursor);
  const res = await api("get", `/admin/monitors?${qs}` as "/admin/monitors", {
    signal,
  });
  return {
    monitors: res.data?.monitors ?? [],
    next_cursor: (res.data?.next_cursor as string | null | undefined) ?? null,
  };
}

export async function setMonitorPaused(
  id: string,
  paused: boolean,
  expectedGeneration: number,
  reason: string,
  idem: string,
) {
  const res = await api(
    "post",
    route(paused ? "/admin/monitors/{id}/pause" : "/admin/monitors/{id}/resume", id),
    { body: { expected_generation: expectedGeneration, reason }, idempotencyKey: idem },
  );
  return res.data ?? null;
}

export interface OutboxFilters {
  state?: "PENDING" | "LEASED" | "SENT" | "DEAD" | "SUPPRESSED";
}

export async function fetchOutbox(
  filters: OutboxFilters,
  cursor: string | null,
  signal?: AbortSignal,
) {
  const qs = new URLSearchParams();
  qs.set("limit", "50");
  if (filters.state) qs.set("state", filters.state);
  if (cursor) qs.set("cursor", cursor);
  const res = await api("get", `/admin/outbox?${qs}` as "/admin/outbox", {
    signal,
  });
  return {
    deliveries: res.data?.deliveries ?? [],
    next_cursor: (res.data?.next_cursor as string | null | undefined) ?? null,
  };
}

export async function retryDelivery(
  id: string,
  expectedVersion: number,
  reason: string,
  idem: string,
) {
  const res = await api("post", route("/admin/outbox/{id}/retry", id), {
    body: { expected_version: expectedVersion, reason },
    idempotencyKey: idem,
  });
  return res.data ?? null;
}

export async function suppressDelivery(
  id: string,
  expectedVersion: number,
  reason: string,
  idem: string,
) {
  const res = await api("post", route("/admin/outbox/{id}/suppress", id), {
    body: { expected_version: expectedVersion, reason },
    idempotencyKey: idem,
  });
  return res.data ?? null;
}

export interface AuditFilters {
  action?: string;
  actor?: string;
  subject?: string;
  from?: string;
  to?: string;
}

export async function fetchAuditEvents(
  filters: AuditFilters,
  cursor: string | null,
  signal?: AbortSignal,
) {
  const qs = new URLSearchParams();
  qs.set("limit", "50");
  for (const k of ["action", "actor", "subject", "from", "to"] as const) {
    if (filters[k]) qs.set(k, filters[k]!);
  }
  if (cursor) qs.set("cursor", cursor);
  const res = await api("get", `/admin/audit-events?${qs}` as "/admin/audit-events", {
    signal,
  });
  return {
    events: res.data?.events ?? [],
    next_cursor: (res.data?.next_cursor as string | null | undefined) ?? null,
  };
}

export async function fetchAuditEvent(id: string, signal?: AbortSignal) {
  const res = await api("get", route("/admin/audit-events/{id}", id), { signal });
  return res.data ?? null;
}
