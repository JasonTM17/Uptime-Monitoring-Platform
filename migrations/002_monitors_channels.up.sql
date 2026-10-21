-- 002_monitors_channels: owned monitor + notification channel schema.
-- quota_budgets is left EMPTY by design: monitor creation must refuse
-- while the singleton row is absent (fail closed); the app seeds it at
-- startup from configured allocation policy, operators may adjust later.

CREATE TABLE uptime.quota_budgets (
  id smallint PRIMARY KEY CHECK (id=1),
  global_monitor_limit integer NOT NULL CHECK (global_monitor_limit BETWEEN 1 AND 10000),
  version bigint NOT NULL DEFAULT 1 CHECK (version>0)
);

CREATE TABLE uptime.monitors (
  id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES uptime.users(id) ON DELETE RESTRICT,
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
  target_url text NOT NULL CHECK (octet_length(target_url)<=2048),
  method text NOT NULL DEFAULT 'GET' CHECK (method='GET'),
  interval_seconds integer NOT NULL CHECK (interval_seconds BETWEEN 60 AND 86400),
  timeout_seconds integer NOT NULL DEFAULT 5 CHECK (timeout_seconds BETWEEN 1 AND 10),
  expected_status integer NULL CHECK (expected_status BETWEEN 200 AND 599),
  is_paused boolean NOT NULL DEFAULT false, deleted_at timestamptz NULL,
  health text NOT NULL DEFAULT 'UNKNOWN' CHECK (health IN ('UNKNOWN','UP','DOWN')),
  failure_streak integer NOT NULL DEFAULT 0 CHECK (failure_streak BETWEEN 0 AND 3),
  success_streak integer NOT NULL DEFAULT 0 CHECK (success_streak BETWEEN 0 AND 2),
  generation bigint NOT NULL DEFAULT 1 CHECK (generation>0),
  last_reserved_sequence bigint NOT NULL DEFAULT 0 CHECK (last_reserved_sequence>=0),
  last_applied_sequence bigint NOT NULL DEFAULT 0 CHECK (last_applied_sequence>=0),
  next_check_at timestamptz NOT NULL,
  last_checked_at timestamptz NULL, last_response_time_ms bigint NULL CHECK (last_response_time_ms>=0),
  last_error_type text NULL, created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(), UNIQUE(id,user_id),
  CHECK (timeout_seconds<interval_seconds), CHECK (last_applied_sequence<=last_reserved_sequence)
);
CREATE INDEX monitors_owner_page ON uptime.monitors(user_id,created_at,id) WHERE deleted_at IS NULL;
CREATE INDEX monitors_due ON uptime.monitors(next_check_at,id) WHERE NOT is_paused AND deleted_at IS NULL;
CREATE INDEX monitors_owner_retained ON uptime.monitors(user_id,id); -- retained cap counts tombstones too

CREATE TABLE uptime.notification_channels (
  id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES uptime.users(id) ON DELETE RESTRICT,
  label text NOT NULL CHECK (length(label) BETWEEN 1 AND 120),
  kind text NOT NULL DEFAULT 'TELEGRAM' CHECK (kind='TELEGRAM'),
  status text NOT NULL DEFAULT 'PENDING_VERIFICATION'
    CHECK (status IN ('PENDING_VERIFICATION','VERIFIED','DISABLED')),
  destination_ciphertext bytea NULL, destination_mask text NULL,
  encryption_key_version integer NULL CHECK (encryption_key_version>0),
  verified_at timestamptz NULL, verification_receipt text NULL,
  enabled boolean NOT NULL DEFAULT false, version bigint NOT NULL DEFAULT 1 CHECK (version>0),
  deleted_at timestamptz NULL, created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(), UNIQUE(id,user_id),
  CHECK (NOT enabled OR (status='VERIFIED' AND deleted_at IS NULL)),
  CHECK (status<>'VERIFIED' OR (destination_ciphertext IS NOT NULL AND verified_at IS NOT NULL
    AND encryption_key_version IS NOT NULL AND verification_receipt IS NOT NULL))
);
CREATE INDEX channels_owner_page ON uptime.notification_channels(user_id,created_at,id) WHERE deleted_at IS NULL;
CREATE INDEX channels_owner_retained ON uptime.notification_channels(user_id,id);
CREATE INDEX channels_pending_all ON uptime.notification_channels(user_id,id) WHERE status='PENDING_VERIFICATION';

CREATE TABLE uptime.monitor_channels (
  monitor_id uuid NOT NULL, channel_id uuid NOT NULL, user_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(monitor_id,channel_id),
  FOREIGN KEY(monitor_id,user_id) REFERENCES uptime.monitors(id,user_id) ON DELETE RESTRICT,
  FOREIGN KEY(channel_id,user_id) REFERENCES uptime.notification_channels(id,user_id) ON DELETE RESTRICT
);
CREATE INDEX monitor_channels_reverse ON uptime.monitor_channels(channel_id,monitor_id);
