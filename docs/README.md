# Documentation index

Tài liệu được nhóm theo API, kiến trúc, triển khai, thiết kế, vận hành, bảo mật, kiểm thử và phát hành. Trang release chỉ ghi nhận trạng thái phân phối sau khi các registry được kiểm chứng.

- [Bắt đầu chạy dự án](../README.md#quick-start) · [Tóm tắt tiếng Việt](readme-vi.md)
- [Hướng dẫn sử dụng](user-guide.md): tài khoản → monitor → incident/thống kê → Telegram → phiên/quản trị, kèm xử lý lỗi.

## Public docs

- [API contract (OpenAPI 3.1.1)](api/openapi.yaml): implemented routes
  đạt parity với `tools/openapi/check-openapi.mjs`; operations tagged
  `planned`/`x-future` là contract drafts, chưa tồn tại ở runtime.
- [Product requirements và scope traceability](product-requirements.md):
  Must/non-goals và các yêu cầu R01–R24.
- [Business rules and implementation map](business-rules.md): identity, ownership, quota, transitions, retry, statistics, retention and administrative recovery, with source/test owners.
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
- [System design and failure cases](architecture/system-design.md): architecture review answers, trust boundaries, twenty failure scenarios and a source/test learning route.
- [SSRF boundary](security/ssrf-boundary.md) and [RBAC matrix](security/rbac-matrix.md): outbound network and authorization boundaries.
- [Frontend testing](testing/frontend.md): browser and UI verification.
- [Container release policy](releases/container-policy.md): image identity,
  publication prerequisites, digest and privacy requirements.
- [Container acceptance](releases/container-acceptance.md): current registry
  verification state and remaining release boundary.
- [Release evidence](releases/v0.1.0-evidence.md): public registry record;
  no local receipts or private planning material.

## Operations

- [Administrative bootstrap and recovery](runbooks/admin-recovery.md).
- [Backup and restore](runbooks/backup-restore.md).
- [Local health and metrics](runbooks/local-operations.md), [notification delivery](runbooks/notification-delivery.md), and [retention](runbooks/retention.md).
- Deployment guides: [Render](deployment/render.md), [Vercel](deployment/vercel.md), [Supabase](deployment/supabase.md), and [free-tier budget](deployment/free-tier-budget.md). Hosted deployment has not been verified by the release evidence.

## Cấu trúc thư mục tài liệu

| Thư mục | Nội dung |
|---|---|
| `api/` | OpenAPI contract |
| `architecture/` | System decisions/failure cases, database và thống kê |
| `deployment/` | Candidate deployment guides and budgets |
| `design/` | UI decisions, inventories, and design handoff |
| `media/` | Product screenshots and demo assets |
| `releases/` | Container policy and public release records |
| `runbooks/` | Local operations, database, notification, retention, and recovery |
| `security/` | SSRF and role authorization boundaries |
| `testing/` | Local acceptance, browser, capacity, and admin security checks |

The root of `docs/` also contains the toolchain guide, product requirements, and engine lifecycle documentation.
