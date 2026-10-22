// C89 trust-gate contract tests. node --test scripts/verify-hosted.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { validateTrust } from "./verify-hosted.mjs";

const base = () => ({
  format: "hosted-candidate-v1",
  source_sha: "a".repeat(40),
  image: { ref: `ghcr.io/jasontm17/uptime-monitoring-platform@sha256:${"b".repeat(64)}` },
  env: {
    APP_ENV: "hosted",
    TRUSTED_ORIGINS: ["https://uptime-demo.vercel.app"],
    TRUSTED_PROXIES: ["100.64.0.0/10"],
    DATABASE_URL: "env:DATABASE_URL",
    ENGINE_DATABASE_URL: "env:ENGINE_DATABASE_URL",
    MIGRATION_DATABASE_URL: "env:MIGRATION_DATABASE_URL",
    CSRF_SIGNING_KEY: "sref:CSRF_SIGNING_KEY",
  },
  engine_conn: { host: "aws-0-x.pooler.supabase.com", port: 5432, mode: "session" },
  migration: { strategy: "deploy-step" },
  services: [{ type: "web", name: "uptime-api", health_check: "/health/live", plan: "free" }],
  endpoints: {},
});

const errs = (mut) => { const c = base(); mut(c); return validateTrust(c); };

test("valid candidate passes", () => {
  assert.deepEqual(validateTrust(base()), []);
});

test("reject latest-tag deploy", () => {
  assert.ok(errs((c) => { c.image.ref = "ghcr.io/x/uptime:latest"; })
    .some((e) => /digest|latest/.test(e)));
});

test("reject tag without digest", () => {
  assert.ok(errs((c) => { c.image.ref = "ghcr.io/x/uptime:v0.1.0"; })
    .some((e) => /digest/.test(e)));
});

test("reject wildcard origin", () => {
  assert.ok(errs((c) => { c.env.TRUSTED_ORIGINS = ["https://*.vercel.app"]; })
    .some((e) => /wildcard|exact/.test(e)));
});

test("reject http origin", () => {
  assert.ok(errs((c) => { c.env.TRUSTED_ORIGINS = ["http://app.example.com"]; })
    .some((e) => /https origin/.test(e)));
});

test("reject empty origins under hosted", () => {
  assert.ok(errs((c) => { c.env.TRUSTED_ORIGINS = []; })
    .some((e) => /empty/.test(e)));
});

test("reject trust-all proxy", () => {
  assert.ok(errs((c) => { c.env.TRUSTED_PROXIES = ["0.0.0.0/0"]; })
    .some((e) => /trust-all/.test(e)));
});

test("reject empty proxy list under hosted", () => {
  assert.ok(errs((c) => { c.env.TRUSTED_PROXIES = []; })
    .some((e) => /rate bucket/.test(e)));
});

test("reject literal DSN without TLS", () => {
  assert.ok(errs((c) => { c.env.DATABASE_URL = "postgres://u:p@h:5432/d?sslmode=disable"; })
    .some((e) => /literal DSN|sslmode/.test(e)));
});

test("reject literal DSN even with TLS (values must be refs)", () => {
  assert.ok(errs((c) => { c.env.MIGRATION_DATABASE_URL = "postgres://u:p@h:5432/d?sslmode=require"; })
    .some((e) => /literal DSN/.test(e)));
});

test("reject transaction-pooler engine connection", () => {
  assert.ok(errs((c) => { c.engine_conn.port = 6543; })
    .some((e) => /session mode :5432/.test(e)));
});

test("reject startup auto-migrate", () => {
  assert.ok(errs((c) => { c.migration.strategy = "startup"; })
    .some((e) => /deploy-step/.test(e)));
});

test("reject missing healthcheck", () => {
  assert.ok(errs((c) => { c.services[0].health_check = "/health/ready"; })
    .some((e) => /health\/live/.test(e)));
});

test("reject extra always-on service", () => {
  assert.ok(errs((c) => { c.services.push({ type: "worker", name: "cron" }); })
    .some((e) => /exactly 1 web service/.test(e)));
});

test("reject secret value in env", () => {
  assert.ok(errs((c) => { c.env.CSRF_SIGNING_KEY = "abc123def456ghi789jkl012mno345"; })
    .some((e) => /secret value/.test(e)));
});
