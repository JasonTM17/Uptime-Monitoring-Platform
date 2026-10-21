import type { components } from "../../lib/api/schema";
import { api } from "../../lib/api/client";

export type MonitorStats = components["schemas"]["MonitorStats"];
export type StatsBucket = components["schemas"]["StatsBucket"];
export type CheckRow = components["schemas"]["CheckHistoryRow"];
export type IncidentRow = components["schemas"]["IncidentRow"];
export type StatsWindow = "24h" | "7d" | "30d";

export async function fetchStats(
  id: string,
  window: StatsWindow,
  signal?: AbortSignal,
): Promise<MonitorStats | null> {
  const res = await api(
    "get",
    `/monitors/${encodeURIComponent(id)}/stats?window=${window}` as "/monitors/{id}/stats",
    { signal },
  );
  return res.data ?? null;
}

export interface ChecksPage {
  checks: CheckRow[];
  page: { next_cursor?: string; has_more?: boolean };
}

export async function fetchChecks(
  id: string,
  cursor: string | null,
  signal?: AbortSignal,
): Promise<ChecksPage> {
  const qs = new URLSearchParams({ limit: "50" });
  if (cursor) qs.set("cursor", cursor);
  const res = await api(
    "get",
    `/monitors/${encodeURIComponent(id)}/checks?${qs}` as "/monitors/{id}/checks",
    { signal },
  );
  const d = res.data;
  return {
    checks: d?.checks ?? [],
    page: d?.page ?? { next_cursor: "", has_more: false },
  };
}

export interface IncidentsPage {
  incidents: IncidentRow[];
  page: { next_cursor?: string; has_more?: boolean };
}

export async function fetchIncidents(
  id: string,
  state: "open" | "resolved" | null,
  cursor: string | null,
  signal?: AbortSignal,
): Promise<IncidentsPage> {
  const qs = new URLSearchParams({ limit: "50" });
  if (state) qs.set("state", state);
  if (cursor) qs.set("cursor", cursor);
  const res = await api(
    "get",
    `/monitors/${encodeURIComponent(id)}/incidents?${qs}` as "/monitors/{id}/incidents",
    { signal },
  );
  const d = res.data;
  return {
    incidents: d?.incidents ?? [],
    page: d?.page ?? { next_cursor: "", has_more: false },
  };
}
