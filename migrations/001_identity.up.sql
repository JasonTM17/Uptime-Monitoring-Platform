-- 001_identity: users + sessions (spec 03 database design, identity block).
CREATE SCHEMA IF NOT EXISTS uptime;

CREATE TABLE uptime.users (
  id uuid PRIMARY KEY,
  email text NOT NULL UNIQUE,
  password_hash text NOT NULL,
  display_name text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','DISABLED')),
  monitor_limit integer NOT NULL DEFAULT 10 CHECK (monitor_limit BETWEEN 0 AND 10000),
  security_version bigint NOT NULL DEFAULT 1 CHECK (security_version > 0),
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  disabled_at timestamptz NULL,
  CHECK (email = lower(btrim(email)) AND length(email) BETWEEN 3 AND 254),
  CHECK ((status='DISABLED') = (disabled_at IS NOT NULL))
);

CREATE TABLE uptime.sessions (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES uptime.users(id) ON DELETE RESTRICT,
  token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash)=32),
  security_version bigint NOT NULL CHECK (security_version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  idle_expires_at timestamptz NOT NULL,
  recent_auth_at timestamptz NULL,
  revoked_at timestamptz NULL,
  device_label text NOT NULL DEFAULT '' CHECK (length(device_label)<=120),
  CHECK (expires_at>created_at AND idle_expires_at<=expires_at)
);

CREATE INDEX sessions_owner_active ON uptime.sessions(user_id,created_at,id) WHERE revoked_at IS NULL;
CREATE INDEX sessions_expiry ON uptime.sessions(expires_at);
