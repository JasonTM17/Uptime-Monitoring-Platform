import type { components } from "../../lib/api/schema";
import { api } from "../../lib/api/client";

export type DashboardSummary = components["schemas"]["DashboardSummary"];
export type Monitor = components["schemas"]["Monitor"];

export interface MonitorPage {
  items: Monitor[];
  has_more: boolean;
  next_cursor: string | null;
}

export interface MonitorFilters {
  health?: "UNKNOWN" | "UP" | "DOWN";
  paused?: "true" | "false";
  q?: string;
}

export async function fetchSummary(
  signal?: AbortSignal,
): Promise<DashboardSummary | null> {
  const res = await api("get", "/dashboard/summary", { signal });
  return res.data ?? null;
}

export async function fetchMonitors(
  filters: MonitorFilters,
  cursor: string | null,
  signal?: AbortSignal,
): Promise<MonitorPage> {
  const qs = new URLSearchParams();
  qs.set("limit", "20");
  if (filters.health) qs.set("health", filters.health);
  if (filters.paused) qs.set("paused", filters.paused);
  if (filters.q) qs.set("q", filters.q);
  if (cursor) qs.set("cursor", cursor);
  const res = await api(
    "get",
    `/monitors?${qs.toString()}` as "/monitors",
    { signal },
  );
  return res.data ?? { items: [], has_more: false, next_cursor: null };
}
