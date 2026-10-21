-- 004_incidents: one open incident per monitor, anchored to the
-- check_runs that opened and resolved it. History survives soft
-- deletion; close_reason distinguishes observed recovery from
-- lifecycle closure (config change / delete are NOT recoveries).
CREATE TABLE uptime.incidents (
  id uuid PRIMARY KEY, monitor_id uuid NOT NULL REFERENCES uptime.monitors(id) ON DELETE RESTRICT,
  opened_check_id uuid NOT NULL, resolved_check_id uuid NULL,
  opened_at timestamptz NOT NULL, resolved_at timestamptz NULL,
  close_reason text NULL CHECK(close_reason IN ('RECOVERED','CONFIG_CHANGED','DELETED')),
  version bigint NOT NULL DEFAULT 1 CHECK(version>0), created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(id,monitor_id),
  FOREIGN KEY(opened_check_id,monitor_id) REFERENCES uptime.check_runs(id,monitor_id) ON DELETE RESTRICT,
  FOREIGN KEY(resolved_check_id,monitor_id) REFERENCES uptime.check_runs(id,monitor_id) ON DELETE RESTRICT,
  CHECK((resolved_at IS NULL AND close_reason IS NULL) OR
    (resolved_at IS NOT NULL AND close_reason IS NOT NULL AND resolved_at>=opened_at))
);
CREATE UNIQUE INDEX incidents_one_open ON uptime.incidents(monitor_id) WHERE resolved_at IS NULL;
CREATE INDEX incidents_history ON uptime.incidents(monitor_id,opened_at,id);
