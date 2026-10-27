# Documentation index

Tài liệu được nhóm theo API, kiến trúc, triển khai, thiết kế, vận hành, bảo mật, kiểm thử và phát hành. Trang release chỉ ghi nhận trạng thái phân phối sau khi các registry được kiểm chứng.

## Public docs

- [API contract (OpenAPI 3.1.1)](api/openapi.yaml): implemented routes
  đạt parity với `tools/openapi/check-openapi.mjs`; operations tagged
  `planned`/`x-future` là contract drafts, chưa tồn tại ở runtime.
- [Product requirements và scope traceability](product-requirements.md):
  Must/non-goals và các yêu cầu R01–R24.
- [Toolchain pins và compatibility](toolchain.md): pinned versions, local
  drift, prerequisites Windows/Linux.
- [Runbook: local và test databases](runbooks/local-database.md):
  Compose profiles, migration job, safe teardown rules.
- [Runbook: notification delivery](runbooks/notification-delivery.md):
  pipeline states, causal ordering, operator dead-letter controls.
- [Runbook: retention](runbooks/retention.md): bounded purge lanes,
  rollup barrier, protected references, operator checks.
- [Runbook: local operations](runbooks/local-operations.md): health
  semantics, bounded metrics catalog, freshness interpretation.
- [Testing và verification](testing.md): local gate commands, check
  semantics, CI boundaries và links tới [capacity protocol](testing/capacity.md).
- [Admin security race matrix](testing/admin-security.md): the
  privileged-recipe linearization order và its concurrency proofs.
- [Engine lifecycle](engine-lifecycle.md): ownership/epochs, durable
  reservation → attempt → atomic finalize pipeline, failure-boundary
  semantics và fencing invariants.
- [Sampled statistics](architecture/statistics.md): denominator
  partition, raw+hourly merge, represented-window contract.
- [Database design](architecture/database.md): ERD, table inventory và
  schema-level invariants của schema `uptime` (dẫn từ `migrations/`).
- [Container release policy](releases/container-policy.md): image identity,
  publication prerequisites, digest and privacy requirements.
- [Container acceptance](releases/container-acceptance.md): current registry
  verification state and remaining release boundary.
- [Release evidence](releases/v0.1.0-evidence.md): public registry record;
  no local receipts or private planning material.

## Cấu trúc thư mục tài liệu

| Thư mục | Nội dung |
|---|---|
| `api/` | OpenAPI contract |
| `architecture/` | Database và thống kê |
| `deployment/` | Candidate deployment guides and budgets |
| `design/` | UI decisions, inventories, and design handoff |
| `media/` | Product screenshots and demo assets |
| `releases/` | Container policy and public release records |
| `runbooks/` | Local operations, database, notification, retention, and recovery |
| `security/` | SSRF and role authorization boundaries |
| `testing/` | Local acceptance, browser, capacity, and admin security checks |

The root of `docs/` also contains the toolchain guide, product requirements, and engine lifecycle documentation.
