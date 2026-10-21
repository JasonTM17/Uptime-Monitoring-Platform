-- 001_identity down: reverse in dependency order. Only ever run against
-- the disposable test database through the gated migrate job.
DROP TABLE IF EXISTS uptime.sessions;
DROP TABLE IF EXISTS uptime.users;
DROP SCHEMA IF EXISTS uptime;
