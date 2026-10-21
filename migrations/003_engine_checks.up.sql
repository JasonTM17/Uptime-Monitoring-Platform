-- 003_engine_checks: durable engine admission + observation model.
-- engine_control is a singleton row; the advisory lock (not the row)
-- is the authority on which process owns writes.
CREATE TABLE uptime.engine_control (
  id smallint PRIMARY KEY CHECK(id=1),
  epoch bigint NOT NULL CHECK(epoch>0),
  owner_instance uuid NULL,
  acquired_at timestamptz NULL,
  heartbeat_at timestamptz NULL
);

CREATE TABLE uptime.schedule_segments (
  id uuid PRIMARY KEY,
  monitor_id uuid NOT NULL REFERENCES uptime.monitors(id) ON DELETE RESTRICT,
  generation bigint NOT NULL CHECK(generation>0),
  starts_at timestamptz NOT NULL,
  ends_at timestamptz NULL,
  interval_seconds integer NOT NULL CHECK(interval_seconds BETWEEN 60 AND 86400),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(id,monitor_id),
  CHECK(ends_at IS NULL OR ends_at>=starts_at)
);
-- At most one open-ended (current) segment per monitor.
CREATE UNIQUE INDEX segments_one_current ON uptime.schedule_segments(monitor_id) WHERE ends_at IS NULL;
CREATE INDEX segments_window ON uptime.schedule_segments(monitor_id,starts_at,ends_at);

CREATE TABLE uptime.check_runs (
  id uuid PRIMARY KEY,
  monitor_id uuid NOT NULL REFERENCES uptime.monitors(id) ON DELETE RESTRICT,
  segment_id uuid NOT NULL,
  slot_at timestamptz NOT NULL,
  generation bigint NOT NULL CHECK(generation>0),
  sequence bigint NOT NULL CHECK(sequence>0),
  engine_epoch bigint NOT NULL CHECK(engine_epoch>0),
  status text NOT NULL CHECK(status IN ('RESERVED','RUNNING','COMPLETED','EXCLUDED','INTERRUPTED','STALE')),
  reserved_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz NULL,
  finished_at timestamptz NULL,
  terminal_reason text NULL,
  UNIQUE(monitor_id,segment_id,slot_at),
  UNIQUE(monitor_id,sequence),
  UNIQUE(id,monitor_id),
  FOREIGN KEY(segment_id,monitor_id) REFERENCES uptime.schedule_segments(id,monitor_id) ON DELETE RESTRICT
);
-- One in-flight run per monitor.
CREATE UNIQUE INDEX runs_one_active ON uptime.check_runs(monitor_id) WHERE status IN ('RESERVED','RUNNING');
CREATE INDEX runs_terminal_retention ON uptime.check_runs(finished_at,id) WHERE finished_at IS NOT NULL;
-- F02: admission window counts EVERY status — a reservation is a charge.
CREATE INDEX runs_admission_window ON uptime.check_runs(reserved_at DESC,id);

CREATE TABLE uptime.check_results (
  check_id uuid PRIMARY KEY,
  monitor_id uuid NOT NULL,
  outcome text NOT NULL CHECK(outcome IN ('SUCCESS','UNEXPECTED_STATUS','DNS_ERROR','CONNECT_ERROR',
    'TLS_ERROR','TIMEOUT','POLICY_BLOCKED','CANCELLED','INTERNAL_ERROR')),
  eligible boolean NOT NULL,
  success boolean NULL,
  http_status integer NULL CHECK(http_status BETWEEN 100 AND 599),
  duration_ms bigint NOT NULL CHECK(duration_ms>=0),
  observed_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  rolled_up_at timestamptz NULL,
  FOREIGN KEY(check_id,monitor_id) REFERENCES uptime.check_runs(id,monitor_id) ON DELETE RESTRICT,
  CHECK((eligible AND success IS NOT NULL) OR (NOT eligible AND success IS NULL)),
  CHECK(eligible = (outcome IN ('SUCCESS','UNEXPECTED_STATUS','DNS_ERROR','CONNECT_ERROR','TLS_ERROR','TIMEOUT'))),
  CHECK((outcome='SUCCESS') = (success IS TRUE))
);
CREATE INDEX results_history ON uptime.check_results(monitor_id,observed_at,check_id);
CREATE INDEX results_rollup_pending ON uptime.check_results(observed_at,check_id) WHERE rolled_up_at IS NULL;

-- Singleton engine_control row seeded at epoch 1 with no owner;
-- first acquisition bumps it and stamps owner identity.
INSERT INTO uptime.engine_control(id,epoch,owner_instance) VALUES (1,1,NULL)
  ON CONFLICT (id) DO NOTHING;
