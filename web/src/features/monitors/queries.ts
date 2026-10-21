import type { components, operations } from "../../lib/api/schema";
import { api, route } from "../../lib/api/client";
import type { Monitor } from "../dashboard/queries";

export type { Monitor };
export type Channel = components["schemas"]["Channel"];
type PatchBody =
  operations["patchMonitor"]["requestBody"]["content"]["application/json"];

export async function getMonitor(id: string, signal?: AbortSignal) {
  const res = await api("get", route("/monitors/{id}", id), { signal });
  return res.data ?? null;
}

export function createMonitor(
  body: components["schemas"]["MonitorCreateInput"],
) {
  return api("post", "/monitors", { body });
}

export function patchMonitor(id: string, body: PatchBody) {
  return api("patch", route("/monitors/{id}", id), { body });
}

export function deleteMonitor(id: string, expectedGeneration: number) {
  return api("delete", route("/monitors/{id}", id), {
    body: { expected_generation: expectedGeneration },
  });
}

export function pauseMonitor(id: string, expectedGeneration: number) {
  return api("post", route("/monitors/{id}/pause", id), {
    body: { expected_generation: expectedGeneration },
  });
}

export function resumeMonitor(id: string, expectedGeneration: number) {
  return api("post", route("/monitors/{id}/resume", id), {
    body: { expected_generation: expectedGeneration },
  });
}

export function replaceChannels(id: string, generation: number, ids: string[]) {
  return api("put", route("/monitors/{id}/notification-channels", id), {
    body: { expected_generation: generation, channel_ids: ids },
  });
}

export async function listChannels(signal?: AbortSignal): Promise<Channel[]> {
  const res = await api("get", "/notification-channels", { signal });
  return res.data?.items ?? [];
}
