# Documentation

Bắt đầu từ luồng sử dụng, sau đó đi sâu vào kiến trúc và quy tắc nghiệp vụ.
Tài liệu kỹ thuật dẫn tới source/test làm chủ hợp đồng; ảnh minh họa, kết quả
kiểm thử và bằng chứng phát hành được phân biệt rõ.

## Start here

| Bạn muốn | Điểm bắt đầu |
| --- | --- |
| Chạy dự án lần đầu | [Quick start](../README.md#quick-start) · [Tóm tắt tiếng Việt](readme-vi.md) |
| Sử dụng monitor, incident và cảnh báo | [Hướng dẫn sử dụng](user-guide.md) |
| Hiểu hệ thống và các quyết định | [Sơ đồ tổng thể và luồng xử lý](architecture/system-design.md) |
| Hiểu phạm vi và các điều kiện cho phép/từ chối | [Requirements](product-requirements.md) · [Business rules](business-rules.md) |
| Phát triển, kiểm thử hoặc vận hành | [Testing](testing.md) · [Operations](#operations) |

## Architecture and contracts

- [System design](architecture/system-design.md): sơ đồ thành phần, luồng check
  và delivery, quyết định kiến trúc, trust boundaries và các tình huống lỗi.
- [Database design](architecture/database.md): ERD, schema và các invariant do
  [migrations](../migrations/) sở hữu.
- [Engine lifecycle](engine-lifecycle.md): ownership, reservation, finalization,
  fencing và recovery.
- [Sampled statistics](architecture/statistics.md): coverage, represented window,
  raw/hourly merge và cách đọc khoảng dữ liệu thiếu.
- [Business rules](business-rules.md): actors, identity, ownership, quota,
  incident, notification, retention và admin, cùng source/test đối chiếu.
- [API contract](api/openapi.yaml): OpenAPI 3.1.1; route đã triển khai do
  [contract checker](../tools/openapi/check-openapi.mjs) kiểm tra parity.
  Operations tagged planned/x-future là draft, không phải endpoint runtime.
- [Product requirements](product-requirements.md): yêu cầu R01–R24, đối chiếu
  các đầu ra và giới hạn kiểm chứng.

## Security

- [SSRF boundary](security/ssrf-boundary.md): input, resolution/dial và network policy.
- [RBAC matrix](security/rbac-matrix.md): catalog permissions, role delegation và các quyền được bảo vệ.
- [Admin security races](testing/admin-security.md): thứ tự linearization và các negative/concurrency oracle.
- [Security reporting](../SECURITY.md): cách báo lỗi mà không công khai dữ liệu nhạy cảm.

## Development and verification

- [Toolchain](toolchain.md): version pins, prerequisites và compatibility.
- [Testing](testing.md): unit, PostgreSQL integration, contract checks, CI và
  yêu cầu database test dùng riêng, có thể hủy.
- [Frontend testing](testing/frontend.md): component, browser, responsive và a11y checks.
- [Local acceptance](testing/local-acceptance.md): harness cô lập và phạm vi
  bằng chứng cho từng lane.
- [Capacity protocol](testing/capacity.md): đo thực tế, fault injection và
  phân biệt projection với kết quả đo.
- [Contributing](../CONTRIBUTING.md): convention và ranh giới thay đổi.

## Operations

- [Local database](runbooks/local-database.md): Compose profiles, migrations,
  disposable tests và teardown đúng phạm vi.
- [Health and metrics](runbooks/local-operations.md): readiness, engine
  freshness và catalog metrics.
- [Notification delivery](runbooks/notification-delivery.md): operator
  verification, retry/lease, causal ordering và dead-letter recovery.
- [Administrative bootstrap/recovery](runbooks/admin-recovery.md): cấp quyền
  đầu tiên và khôi phục truy cập có audit.
- [Retention](runbooks/retention.md): rollup barrier, protected references và
  các purge lane có giới hạn.
- [Backup and restore](runbooks/backup-restore.md): chuẩn bị và kiểm tra khôi phục.

## Releases and deployment

- [Container policy](releases/container-policy.md): build identity,
  publication prerequisites, digest và privacy.
- [Container acceptance](releases/container-acceptance.md) và
  [local acceptance evidence](releases/local-acceptance.md): điều kiện và
  phạm vi kiểm chứng.
- [Release evidence](releases/v0.1.0-evidence.md): source revision, digest và
  trạng thái registry của artifact đã phát hành. Image đó không tự chứa các
  thay đổi source về sau.
- Candidate deployment guides: [Render](deployment/render.md),
  [Vercel](deployment/vercel.md), [Supabase](deployment/supabase.md) và
  [free-tier budget](deployment/free-tier-budget.md). Hosted runtime chưa được
  xác minh bằng bằng chứng phát hành hiện có.

## Product media and design

- [Screenshots/GIFs](../README.md#screenshots-and-demo) và
  [media manifest](media/manifest.json): capture từ fixture cục bộ, với
  provenance/hash cho từng artifact.
- [Design decisions](design/design-decisions.md),
  [screen inventory](design/screen-inventory.md) và
  [state matrix](design/state-matrix.md): quyết định giao diện và trạng thái cần
  thể hiện. Concept design không thay thế bằng chứng ứng dụng chạy thật.
- [Architecture diagrams](architecture/system-design.md): SVG chỉnh sửa được
  và PNG; minh họa từ source, không phải runtime capture.

## Directory map

| Thư mục | Trách nhiệm |
| --- | --- |
| api/ | HTTP contract |
| architecture/ | System diagrams, decisions, database và statistics |
| security/ | Outbound và authorization boundaries |
| runbooks/ | Database, health, delivery, retention và recovery |
| testing/ | Browser, integration/acceptance, admin races và capacity |
| releases/ | Release policy và evidence gắn với artifact cụ thể |
| deployment/ | Candidate hosting guides và budget |
| design/ | Product design decisions và UI state contracts |
| media/ | Runtime captures và provenance |

Requirements, business rules, toolchain, testing và user guide nằm ở gốc docs/
để truy cập nhanh từ README và các route phía trên.
