# Uptime Monitoring Platform — Tóm tắt tiếng Việt

Dự án cá nhân học sâu backend Go: giám sát uptime HTTP(S) công khai,
cảnh báo sự cố, quản trị nâng cao và dashboard React.

**Trạng thái: đã hoàn thành acceptance cục bộ; phân phối bên ngoài đang chờ.**
Toàn bộ sản phẩm chạy được cục bộ trên harness compose với các gate có bằng
chứng. Việc publish container và deploy hosted còn chặn ở các điều kiện
thuộc quyền chủ repo (chọn license, tài khoản registry, quyền publish).

## Sản phẩm đã có

- Người dùng quản lý monitor HTTP(S), xem uptime/latency theo mẫu lấy,
  theo dõi sự cố và nhận thông báo Telegram đã xác minh.
- Quản trị viên có phân quyền tường minh: tài khoản, phiên, quota, sức
  khỏe vận hành, vai trò và lịch sử audit append-only.
- Backend Go + PostgreSQL: scheduler giới hạn, worker bounded, checker
  chống SSRF theo kết nối, incident/outbox transactional.
- Frontend React + TypeScript: responsive, có trạng thái và hỗ trợ a11y.

## Bằng chứng và media

Ảnh chụp và GIF trong [`media/`](media/) được capture từ ứng dụng thật
chạy trên harness cục bộ deterministic (tài khoản demo tổng hợp, target
fixture cô lập) — không phải mockup. Manifest có hash và provenance cho
từng artifact.

Chưa có deploy hosted hay publish registry được xác nhận — xem
[`releases/container-policy.md`](releases/container-policy.md) và
[`deployment/`](deployment/) cho trạng thái hiện tại và các blocker.

## Chạy cục bộ

Xem [`README.md`](../README.md) (tiếng Anh) và
[`runbooks/local-operations.md`](runbooks/local-operations.md).
