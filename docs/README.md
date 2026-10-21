# Documentation index

Project đang ở giai đoạn **active implementation**. Auth/session,
owned monitor APIs và notification channels đã có kèm contract tests;
chưa có engine, delivery, admin hay public deployment để kiểm chứng.

## Public docs

- [API contract (OpenAPI 3.1.1)](api/openapi.yaml): implemented routes
  đạt parity với `tools/openapi/check-openapi.mjs`; operations tagged
  `planned`/`x-future` là contract drafts, chưa tồn tại ở runtime.
- [Product requirements và scope traceability](product-requirements.md):
  Must/non-goals, R01–R24 map tới phase/gate, 15 deliverables.
- [Toolchain pins và compatibility](toolchain.md): pinned versions, local
  drift, prerequisites Windows/Linux.
- [Runbook: local và test databases](runbooks/local-database.md):
  Compose profiles, migration job, safe teardown rules.
- [Runbook: notification delivery](runbooks/notification-delivery.md):
  pipeline states, causal ordering, operator dead-letter controls.
- [Runbook: retention](runbooks/retention.md): bounded purge lanes,
  rollup barrier, protected references, operator checks.
- [Testing và verification](testing.md): local gate commands, check
  semantics, CI honesty.
- [Admin security race matrix](testing/admin-security.md): the
  privileged-recipe linearization order và its concurrency proofs.
- [Engine lifecycle](engine-lifecycle.md): ownership/epochs, durable
- [Sampled statistics](architecture/statistics.md): denominator
  partition, raw+hourly merge, represented-window contract.
  reservation → attempt → atomic finalize pipeline, failure-boundary
  semantics và fencing invariants.

## Private planning material

Bộ plan chi tiết (11 phases/93 commits), research, review evidence và
execution ledgers sống trong thư mục planning local của workspace; chúng là
private working material, không được link/publish từ public docs. Các thư mục
API/runbooks/media tiếp theo sẽ được tạo cùng commit triển khai liên quan.
