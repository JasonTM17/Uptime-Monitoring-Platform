ALTER TABLE uptime.notification_outbox
  DROP CONSTRAINT IF EXISTS notification_outbox_rate_limit_refusals_check,
  DROP COLUMN IF EXISTS rate_limit_refusals;
