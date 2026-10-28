# Hướng dẫn sử dụng và xử lý tình huống

Hướng dẫn đi từ tài khoản mới đến giám sát sự cố, nhận cảnh báo và quản lý phiên.
Chạy ứng dụng theo [Quick start](../README.md#quick-start) trước.
[Quy tắc nghiệp vụ](business-rules.md) dành cho người phát triển;
[OpenAPI](api/openapi.yaml) là hợp đồng cho API client.

## 1. Tạo tài khoản và đăng nhập

Đăng ký email, mật khẩu và tên hiển thị. Email được bỏ khoảng trắng hai đầu và
chuyển thành chữ thường; không bỏ dấu cộng/dấu chấm theo từng nhà cung cấp.
Mật khẩu có 12–128 ký tự Unicode và không được tự động trim. Không đặt thông
tin bí mật vào tên hiển thị hoặc tên monitor. Xem
[chính sách đăng ký](../internal/auth/registration.go).

Đăng ký tạo người dùng thông thường. Quyền quản trị cần được cấp riêng theo
[quy trình bootstrap](runbooks/admin-recovery.md); nhập role vào request không
tạo quyền. Đăng ký xong, đăng nhập bằng tài khoản vừa tạo.

Sai mật khẩu, tài khoản không tồn tại hoặc bị khóa đều không được cấp phiên.
Khi bị giới hạn đăng nhập, chờ theo phản hồi thay vì gửi lặp. Phiên có hạn dùng
tuyệt đối và hạn dùng khi không hoạt động. Browser phải dùng cookie, CSRF và
origin phù hợp với cấu hình ứng dụng.

Ứng dụng chưa có luồng tự đặt lại mật khẩu qua email, xác minh email hay chỉnh
sửa hồ sơ. CLI recovery quản trị chỉ cấp quyền cho tài khoản ACTIVE đã tồn tại;
nó không khôi phục mật khẩu của tài khoản đó.

## 2. Tạo và quản lý monitor

Trong **Monitors**, tạo monitor với tên dễ nhận biết, URL HTTP(S) công khai,
chu kỳ kiểm tra và timeout. Checker dùng GET. Không chỉ định expected status
thì phản hồi 2xx là thành công; nếu đặt một mã thì phản hồi phải đúng mã đó.
Giới hạn nhập liệu nằm trong [validation](../internal/monitor/validation.go).

URL đúng cú pháp chưa chắc được phép truy cập. Localhost, mạng riêng, dịch vụ
metadata và các đích/redirect bị policy chặn không được mở quyền bằng cách đổi
cách viết URL. Xem [SSRF boundary](security/ssrf-boundary.md).

Monitor mới có health UNKNOWN. Lưu thành công không có nghĩa đã chạy check hay
website đang UP. Nếu dữ liệu đứng yên, kiểm tra
[readiness và engine freshness](runbooks/local-operations.md) trước khi kết
luận endpoint lỗi.

| Thao tác | Điều cần hiểu |
| --- | --- |
| Sửa | Nếu có thay đổi đồng thời, refresh rồi áp dụng lại thay đổi có chủ đích; không dùng generation cũ để ghi đè. |
| Pause | Dừng lịch mới, không báo website DOWN. Incident mở được đóng vì thay đổi cấu hình, không phải phục hồi. |
| Resume | Cho phép scheduler xét chạy lại, không bảo đảm check ngay. DOWN cũ về UNKNOWN để xác lập sự cố mới bằng quan sát mới. |
| Delete | Xóa mềm và dừng lịch; monitor biến khỏi danh sách. Không có nghĩa đã giải phóng toàn bộ dữ liệu hoặc mọi quota. |

Monitor pause vẫn chiếm quota monitor còn tồn tại. Xóa có thể giải phóng quota
này nhưng bản ghi giữ lại vẫn chịu giới hạn allocation. Phân biệt
`QUOTA_EXCEEDED` với `ALLOCATION_LIMIT_REACHED`; không tạo/xóa lặp để thử vượt
giới hạn. Admin cũng không được đặt quota thấp hơn số monitor hiện dùng. Xem
[quy tắc quota](business-rules.md#monitor-lifecycle-and-quota).

## 3. Đọc health, incident và thống kê

Ba lần thất bại hợp lệ liên tiếp mở incident; hai lần thành công hợp lệ liên
tiếp khi DOWN xác nhận phục hồi. Thành công đầu tiên từ UNKNOWN chỉ xác lập UP.
Lỗi nội bộ collector, hủy chạy hoặc bị policy chặn không phải bằng chứng
website DOWN. Xem [bảng chuyển trạng thái](business-rules.md#observations-and-incident-decisions).

Trong trang chi tiết, đọc lịch sử check, incident và khoảng dữ liệu đang xem.
`close_reason=RECOVERED` là phục hồi quan sát được; `CONFIG_CHANGED` hoặc
`DELETED` là đóng do quản lý. Incident đóng chưa đủ để kết luận website phục hồi.

**Sample uptime** là tỷ lệ thành công trong check hợp lệ đã quan sát.
**Coverage** cho biết bao nhiêu lịch kiểm tra kỳ vọng có quan sát hợp lệ.
Uptime cao với coverage thấp cần được xem thận trọng. Không có dữ liệu không
có nghĩa là 100%; khoảng trống/partial không được nối thành dữ liệu giả. Xem
[công thức và retention](architecture/statistics.md).

Trang Incidents hiện dùng danh sách sự cố gần đây có giới hạn. Để duyệt lịch sử
của từng monitor theo trạng thái và cursor, dùng endpoint được mô tả trong
[OpenAPI](api/openapi.yaml); danh sách gần đây không phải toàn bộ lịch sử.

## 4. Cấu hình Telegram và gửi thử

1. Trong **Channels**, tạo nhãn kênh, không nhập chat ID hoặc bot token vào nhãn.
2. Nhờ operator xác minh điểm nhận theo [notification runbook](runbooks/notification-delivery.md).
   PENDING_VERIFICATION chưa gửi được cảnh báo.
3. Khi kênh VERIFIED và enabled, gắn kênh vào monitor. Cả hai phải cùng chủ sở
   hữu; một kênh không hợp lệ làm toàn bộ lần gắn bị từ chối.
4. Chọn monitor đã gắn trong **Send test**. Nếu cần xác nhận mật khẩu, xác nhận
   rồi chủ động bấm gửi lại; bước xác nhận không tự gửi thông báo.
5. **Queued / PENDING** chỉ xác nhận intent đã lưu. Kiểm tra Telegram và nhờ
   operator xem delivery; chưa có provider confirmation thì chưa gọi là gửi thành công.

Test-send có cooldown theo kênh và giới hạn intent đang chờ. Gặp 429 thì chờ;
409 thì kiểm tra binding/trạng thái; 401 thì đăng nhập lại. Request đang chạy
không được tạo intent nếu phiên đã bị thu hồi trước điểm kiểm tra quyền trong
transaction.

Xóa kênh đang chờ xác minh không giải phóng giới hạn pending. Liên hệ operator
để xử lý xác minh thay vì tạo nhãn liên tục. Kênh disable/xóa không được gửi
như recipient hợp lệ.

RECOVERY giữ thứ tự sau DOWN. Nếu DOWN bị DEAD, RECOVERY có thể đang chờ;
retry/suppress cần quyền quản trị delivery. Retry có thể gây thông báo lặp nếu
provider đã nhận nhưng ACK bị mất. Không có bảo đảm exactly-once; xem
[delivery runbook](runbooks/notification-delivery.md).

## 5. Quản lý phiên và tài khoản

Trong **Settings**, xem hồ sơ do server quản lý, quota và danh sách phiên.
Thu hồi phiên lạ; thu hồi phiên hiện tại thì phải đăng nhập lại. Thu hồi tất cả
phiên cần xác nhận mật khẩu và kết thúc cả phiên hiện tại. Đóng tab không
tương đương thu hồi phiên trên server.

Tài khoản suspend không tiếp tục thao tác bằng phiên cũ. Restore cho phép đăng
nhập mới; không phục hồi phiên đã thu hồi hay tự resume monitor do người dùng
pause. Mất quyền quản trị thì dùng [recovery](runbooks/admin-recovery.md), không
sửa role từ browser.

## 6. Dành cho quản trị viên

Console chỉ hiện nhóm chức năng phù hợp với quyền hiện tại. Server kiểm tra
quyền mỗi thao tác; tên role/menu không thay thế kiểm tra đó. Xem
[ma trận RBAC](security/rbac-matrix.md).

Thao tác nhạy cảm cần recent-auth, lý do và phiên bản hiện tại. Khi stale
version, đọc lại trạng thái trước khi quyết định gửi tiếp. Không được loại bỏ
SUPER_ADMIN hoạt động cuối cùng qua quản trị thông thường. Kiểm tra audit sau
thay đổi quyền, trạng thái, quota hoặc delivery. Tìm runbook trong
[docs index](README.md#operations).

## 7. Tra lỗi và giới hạn

| Biểu hiện | Bước xử lý |
| --- | --- |
| 401 | Đăng nhập lại; phiên hết hạn/bị thu hồi hoặc authority tài khoản thay đổi. |
| 403 / REAUTH_REQUIRED | Xác nhận mật khẩu cho thao tác được phép; nếu thiếu permission, nhờ admin đúng quyền. |
| 403 / CSRF_REJECTED | Kiểm tra origin frontend, cookie và proxy theo Quick start. |
| 404 | Tài nguyên không tồn tại/đã xóa/không thuộc tài khoản; không thử dò ID khác. |
| 409 | Đọc error.code: refresh khi conflict; kiểm tra quota hoặc binding nếu thuộc nhóm đó. |
| 422 | Sửa trường được chỉ rõ, không gửi lại dữ liệu y hệt. |
| 429 | Chờ giới hạn/cooldown, không gửi vòng lặp. |
| 5xx hoặc stale | Giữ request ID, thời điểm và thao tác; operator kiểm tra DB/engine/queue. Không gửi cookie/token trong báo lỗi. |

Code/payload chính xác thuộc [OpenAPI](api/openapi.yaml) và
[HTTP error contract](../internal/platform/httpserver/json.go).
Kiểm thử UI với fixture không tự chứng minh Telegram thật hoặc hosted runtime.
Phần đã có và chưa xác minh được tách rõ trong [requirements](product-requirements.md)
và [release evidence](releases/v0.1.0-evidence.md).
