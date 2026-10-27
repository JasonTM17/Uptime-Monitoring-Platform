ALTER TABLE uptime.notification_outbox
  ADD COLUMN rate_limit_refusals integer NOT NULL DEFAULT 0,
  ADD CONSTRAINT notification_outbox_rate_limit_refusals_check
    CHECK (rate_limit_refusals >= 0 AND rate_limit_refusals <= attempts);
