CREATE TABLE uptime.hourly_stats (
  monitor_id uuid NOT NULL REFERENCES uptime.monitors(id) ON DELETE RESTRICT,
  bucket_start timestamptz NOT NULL,
  valid_samples bigint NOT NULL DEFAULT 0 CHECK(valid_samples>=0),
  successes bigint NOT NULL DEFAULT 0 CHECK(successes>=0),
  failures bigint NOT NULL DEFAULT 0 CHECK(failures>=0),
  excluded_samples bigint NOT NULL DEFAULT 0 CHECK(excluded_samples>=0),
  duration_sum_ms bigint NOT NULL DEFAULT 0 CHECK(duration_sum_ms>=0),
  duration_count bigint NOT NULL DEFAULT 0 CHECK(duration_count>=0),
  first_observed_at timestamptz NULL,
  last_observed_at timestamptz NULL,
  finalized_through timestamptz NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(monitor_id,bucket_start),
  CHECK(valid_samples=successes+failures),
  CHECK(bucket_start=date_trunc('hour',bucket_start AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')
);
