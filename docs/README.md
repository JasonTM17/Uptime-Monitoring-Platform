# Documentation index

Project đang ở giai đoạn **early implementation — foundation phase**. Go
module, toolchain pins và local/test PostgreSQL Compose đã có; chưa có API
endpoints, runtime screenshots hay public deployment để kiểm chứng.

## Public docs

- [Product requirements và scope traceability](product-requirements.md):
  Must/non-goals, R01–R24 map tới phase/gate, 15 deliverables.
- [Toolchain pins và compatibility](toolchain.md): pinned versions, local
  drift, prerequisites Windows/Linux.
- [Runbook: local và test databases](runbooks/local-database.md):
  Compose profiles, migration job, safe teardown rules.

## Private planning material

Bộ plan chi tiết (11 phases/93 commits), research, review evidence và
execution ledgers sống trong thư mục planning local của workspace; chúng là
private working material, không được link/publish từ public docs. Các thư mục
API/runbooks/media tiếp theo sẽ được tạo cùng commit triển khai liên quan.
