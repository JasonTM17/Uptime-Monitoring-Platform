-- 007_admin: RBAC catalog, presets, security anchor, append-only
-- audit, privileged idempotency (spec 03 database design, admin block).

CREATE TABLE uptime.permissions (id text PRIMARY KEY, description text NOT NULL);
CREATE TABLE uptime.roles (
  id uuid PRIMARY KEY, code text NOT NULL UNIQUE, name text NOT NULL,
  is_preset boolean NOT NULL DEFAULT false, version bigint NOT NULL DEFAULT 1 CHECK(version>0),
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE uptime.role_permissions (
  role_id uuid NOT NULL REFERENCES uptime.roles(id) ON DELETE RESTRICT,
  permission_id text NOT NULL REFERENCES uptime.permissions(id) ON DELETE RESTRICT,
  PRIMARY KEY(role_id,permission_id)
);
CREATE TABLE uptime.user_roles (
  user_id uuid NOT NULL REFERENCES uptime.users(id) ON DELETE RESTRICT,
  role_id uuid NOT NULL REFERENCES uptime.roles(id) ON DELETE RESTRICT,
  assigned_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(user_id,role_id)
);
CREATE INDEX user_roles_reverse ON uptime.user_roles(role_id,user_id);
CREATE TABLE uptime.security_anchor (id smallint PRIMARY KEY CHECK(id=1), version bigint NOT NULL DEFAULT 1 CHECK(version>0));
CREATE TABLE uptime.audit_events (
  id uuid PRIMARY KEY, actor_id uuid NULL REFERENCES uptime.users(id) ON DELETE RESTRICT,
  actor_kind text NOT NULL CHECK(actor_kind IN ('USER','CLI','SYSTEM')),
  action text NOT NULL, subject_type text NOT NULL, subject_id text NOT NULL,
  reason text NOT NULL CHECK(length(reason) BETWEEN 1 AND 500),
  outcome text NOT NULL CHECK(outcome IN ('SUCCESS','DENIED','FAILURE')),
  safe_diff jsonb NOT NULL DEFAULT '{}'::jsonb CHECK(jsonb_typeof(safe_diff)='object'),
  request_id text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_time ON uptime.audit_events(created_at,id);
CREATE INDEX audit_actor_time ON uptime.audit_events(actor_id,created_at,id);
CREATE INDEX audit_subject_time ON uptime.audit_events(subject_type,subject_id,created_at,id);
CREATE TABLE uptime.admin_idempotency (
  actor_id uuid NOT NULL REFERENCES uptime.users(id) ON DELETE RESTRICT,
  action text NOT NULL, target_id text NOT NULL, key_hash bytea NOT NULL,
  request_hash bytea NOT NULL, safe_response jsonb NOT NULL,
  http_status integer NOT NULL CHECK(http_status BETWEEN 200 AND 299),
  created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
  PRIMARY KEY(actor_id,action,target_id,key_hash), CHECK(expires_at>created_at)
);
CREATE INDEX admin_idempotency_expiry ON uptime.admin_idempotency(expires_at);

-- Canonical permission catalog (spec 07 security-admin-rbac matrix).
-- ON CONFLICT DO NOTHING: a re-run never overwrites an operator-adjusted
-- catalog or grants.
INSERT INTO uptime.permissions (id, description) VALUES
  ('platform:read','Read safe platform aggregates, counts and health freshness'),
  ('users:read','Read the user inventory, account status and safe counts'),
  ('users:manage','Suspend and restore user accounts'),
  ('sessions:manage','Revoke user sessions'),
  ('quotas:manage','Adjust per-user resource quotas'),
  ('roles:read','Read the role and permission catalog'),
  ('roles:manage','Create and edit bounded custom roles and assignments'),
  ('monitors:global:read','Read redacted global monitor inventory'),
  ('monitors:operate','Pause and resume any monitor'),
  ('operations:read','Read engine, queue and retention operational health'),
  ('deliveries:read','Read the notification outbox stream'),
  ('deliveries:retry','Retry dead or eligible deliveries'),
  ('deliveries:suppress','Suppress a delivery and its causal chain'),
  ('audit:read','Read audit events and redacted diffs')
ON CONFLICT (id) DO NOTHING;

-- Preset roles: deterministic UUIDs, seeded once; never re-asserted
-- over modified assignments.
INSERT INTO uptime.roles (id, code, name, is_preset) VALUES
  ('00000000-0000-4000-8000-000000000001','VIEWER','Viewer',true),
  ('00000000-0000-4000-8000-000000000002','SUPPORT','Support',true),
  ('00000000-0000-4000-8000-000000000003','OPERATOR','Operator',true),
  ('00000000-0000-4000-8000-000000000004','SECURITY_ADMIN','Security admin',true),
  ('00000000-0000-4000-8000-000000000005','SUPER_ADMIN','Super admin',true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO uptime.role_permissions (role_id, permission_id) VALUES
  ('00000000-0000-4000-8000-000000000001','platform:read'),
  ('00000000-0000-4000-8000-000000000001','monitors:global:read'),
  ('00000000-0000-4000-8000-000000000001','operations:read'),
  ('00000000-0000-4000-8000-000000000002','platform:read'),
  ('00000000-0000-4000-8000-000000000002','users:read'),
  ('00000000-0000-4000-8000-000000000002','monitors:global:read'),
  ('00000000-0000-4000-8000-000000000002','operations:read'),
  ('00000000-0000-4000-8000-000000000002','deliveries:read'),
  ('00000000-0000-4000-8000-000000000003','platform:read'),
  ('00000000-0000-4000-8000-000000000003','monitors:global:read'),
  ('00000000-0000-4000-8000-000000000003','monitors:operate'),
  ('00000000-0000-4000-8000-000000000003','operations:read'),
  ('00000000-0000-4000-8000-000000000003','deliveries:read'),
  ('00000000-0000-4000-8000-000000000003','deliveries:retry'),
  ('00000000-0000-4000-8000-000000000003','deliveries:suppress'),
  ('00000000-0000-4000-8000-000000000004','platform:read'),
  ('00000000-0000-4000-8000-000000000004','users:read'),
  ('00000000-0000-4000-8000-000000000004','users:manage'),
  ('00000000-0000-4000-8000-000000000004','sessions:manage'),
  ('00000000-0000-4000-8000-000000000004','roles:read'),
  ('00000000-0000-4000-8000-000000000004','monitors:global:read'),
  ('00000000-0000-4000-8000-000000000004','operations:read'),
  ('00000000-0000-4000-8000-000000000004','audit:read'),
  ('00000000-0000-4000-8000-000000000005','platform:read'),
  ('00000000-0000-4000-8000-000000000005','users:read'),
  ('00000000-0000-4000-8000-000000000005','users:manage'),
  ('00000000-0000-4000-8000-000000000005','sessions:manage'),
  ('00000000-0000-4000-8000-000000000005','quotas:manage'),
  ('00000000-0000-4000-8000-000000000005','roles:read'),
  ('00000000-0000-4000-8000-000000000005','roles:manage'),
  ('00000000-0000-4000-8000-000000000005','monitors:global:read'),
  ('00000000-0000-4000-8000-000000000005','monitors:operate'),
  ('00000000-0000-4000-8000-000000000005','operations:read'),
  ('00000000-0000-4000-8000-000000000005','deliveries:read'),
  ('00000000-0000-4000-8000-000000000005','deliveries:retry'),
  ('00000000-0000-4000-8000-000000000005','deliveries:suppress'),
  ('00000000-0000-4000-8000-000000000005','audit:read')
ON CONFLICT (role_id,permission_id) DO NOTHING;

INSERT INTO uptime.security_anchor (id, version) VALUES (1,1)
ON CONFLICT (id) DO NOTHING;

-- Append-only audit boundary: the application role may read and append,
-- never update, delete or truncate. The role itself is created by
-- operator bootstrap (spec 03); grant only when it exists so migrations
-- stay runnable on fresh disposable databases.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='uptime_app') THEN
    REVOKE UPDATE, DELETE, TRUNCATE ON uptime.audit_events FROM uptime_app;
    GRANT SELECT, INSERT ON uptime.audit_events TO uptime_app;
  END IF;
END $$;
