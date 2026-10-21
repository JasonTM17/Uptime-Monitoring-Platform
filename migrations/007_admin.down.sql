-- 007_admin down: reverse dependency order — joins first, then
-- audit/idempotency/anchor, then roles/permissions. Destructive; run
-- only on disposable databases (migrate-entrypoint enforces this).
DROP TABLE IF EXISTS uptime.user_roles;
DROP TABLE IF EXISTS uptime.role_permissions;
DROP TABLE IF EXISTS uptime.admin_idempotency;
DROP TABLE IF EXISTS uptime.audit_events;
DROP TABLE IF EXISTS uptime.security_anchor;
DROP TABLE IF EXISTS uptime.roles;
DROP TABLE IF EXISTS uptime.permissions;
