import type { components } from "../../lib/api/schema";
import { api, route } from "../../lib/api/client";

export type Channel = components["schemas"]["Channel"];
export type ChannelStatus = NonNullable<Channel["status"]>;

export async function fetchChannels(signal?: AbortSignal): Promise<Channel[]> {
  const res = await api("get", "/notification-channels", { signal });
  return res.data?.items ?? [];
}

export async function createChannel(label: string) {
  const res = await api("post", "/notification-channels", {
    body: { label },
  });
  return res.data ?? null;
}

export async function disableChannel(id: string, expectedVersion: number) {
  const res = await api(
    "post",
    route("/notification-channels/{id}/disable", id),
    { body: { expected_version: expectedVersion } },
  );
  return res.data ?? null;
}

export async function deleteChannel(id: string, expectedVersion: number) {
  await api("delete", route("/notification-channels/{id}", id), {
    body: { expected_version: expectedVersion },
  });
}

export interface TestSendResult {
  kind: "queued" | "deduplicated";
  intentId?: string;
  state?: string;
}

// Explicit test-send. 202 = a new intent was persisted (PENDING — queued,
// not delivered); 200 = the same-window duplicate stands. 409 = the
// channel is not bound to that monitor or not verified.
export async function testChannel(
  channelId: string,
  monitorId: string,
): Promise<TestSendResult> {
  const res = await api(
    "post",
    route("/notification-channels/{id}/test", channelId),
    { body: { monitor_id: monitorId } },
  );
  const d = res.data as Record<string, unknown> | undefined;
  if (d?.deduplicated === true) return { kind: "deduplicated" };
  return {
    kind: "queued",
    intentId: typeof d?.intent_id === "string" ? d.intent_id : undefined,
    state: typeof d?.state === "string" ? d.state : undefined,
  };
}
