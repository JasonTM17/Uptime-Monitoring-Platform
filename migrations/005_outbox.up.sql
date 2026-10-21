-- 005_outbox: durable notification intent. One logical event per
-- incident+kind+channel; recovery chains to its DOWN predecessor.
-- safe_payload carries only non-secret projections — never tokens,
-- chat IDs, or raw target URLs.
CREATE TABLE uptime.notification_outbox (
  id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES uptime.users(id) ON DELETE RESTRICT,
  monitor_id uuid NOT NULL, incident_id uuid NULL,
  channel_id uuid NOT NULL, event_kind text NOT NULL CHECK(event_kind IN ('DOWN','RECOVERY','TEST')),
  event_key text NOT NULL UNIQUE, predecessor_id uuid NULL REFERENCES uptime.notification_outbox(id) ON DELETE RESTRICT,
  channel_version bigint NOT NULL CHECK(channel_version>0), payload_version integer NOT NULL DEFAULT 1,
  safe_payload jsonb NOT NULL CHECK(jsonb_typeof(safe_payload)='object'),
  state text NOT NULL DEFAULT 'PENDING' CHECK(state IN ('PENDING','LEASED','SENT','DEAD','SUPPRESSED')),
  attempts integer NOT NULL DEFAULT 0 CHECK(attempts>=0), next_attempt_at timestamptz NOT NULL DEFAULT now(),
  lease_token uuid NULL, lease_expires_at timestamptz NULL,
  last_error_code text NULL, sent_at timestamptz NULL,
  version bigint NOT NULL DEFAULT 1 CHECK(version>0), created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY(incident_id,monitor_id) REFERENCES uptime.incidents(id,monitor_id) ON DELETE RESTRICT,
  FOREIGN KEY(monitor_id,user_id) REFERENCES uptime.monitors(id,user_id) ON DELETE RESTRICT,
  FOREIGN KEY(channel_id,user_id) REFERENCES uptime.notification_channels(id,user_id) ON DELETE RESTRICT,
  CHECK((state='LEASED') = (lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)),
  CHECK((event_kind='TEST') OR incident_id IS NOT NULL), CHECK(predecessor_id IS NULL OR predecessor_id<>id)
);
CREATE UNIQUE INDEX outbox_logical_event ON uptime.notification_outbox(incident_id,event_kind,channel_id) WHERE event_kind<>'TEST';
CREATE INDEX outbox_due ON uptime.notification_outbox(next_attempt_at,created_at,id) WHERE state='PENDING';
CREATE INDEX outbox_expired_lease ON uptime.notification_outbox(lease_expires_at,id) WHERE state='LEASED';
CREATE INDEX outbox_owner_page ON uptime.notification_outbox(user_id,created_at,id);
