# Báo cáo đồ án: LMS Software Security Simulator

## 1. Giới thiệu

Đồ án này xây dựng một mô phỏng về bảo mật phần mềm trong hệ thống LMS (Learning Management System), với trọng tâm là mô hình hóa các tình huống xác thực người dùng, phát triển luồng thông báo email và kiểm tra các lỗi bảo mật trong mã C. Mục tiêu của dự án là minh họa quy trình kiểm chứng an ninh phần mềm từ mức mô hình logic đến mức triển khai mã nguồn và kiểm thử thực tế.

## 2. Vấn đề nghiên cứu

Hệ thống học tập trên Internet thường phải quản lý nhiều thành phần: tài khoản người dùng, session, xác thực, thông báo và dữ liệu. Các vấn đề bảo mật có thể xảy ra ở nhiều lớp, như:

- xác thực không đúng cách
- session không được kiểm soát tốt
- lỗi truy cập bộ nhớ trong mã C
- thiếu kiểm tra ràng buộc của input

Do đó, đồ án tập trung vào việc xây dựng một công cụ mô phỏng cho phép quan sát cách hệ thống chuyển đổi trạng thái, cách ràng buộc được kiểm tra và cách lỗi như negative length trong memcpy có thể bị phát hiện.

## 3. Mục tiêu đồ án

- Thiết kế mô hình xác thực tài khoản và email notification.
- Mô phỏng trạng thái bằng Kripke model.
- Chứng minh ràng buộc bằng Z3 SMT.
- Phân tích ví dụ C vulnerable và safe bằng các công cụ hiện đại.
- Tạo giao diện trực quan để người dùng xem kết quả mô phỏng.

## 4. Kiến trúc hệ thống

Dự án được tổ chức thành các module chính:

- `src/modules/authentication.py`: xử lý đăng nhập, logout, khóa tài khoản, hash mật khẩu.
- `src/modules/email_notification.py`: mô phỏng email notification và retry logic.
- `src/verification/constraints.py`: định nghĩa các ràng buộc bảo mật.
- `src/verification/kripke.py`: mô hình Kripke cho auth và email workflow.
- `src/c_analysis/runner.py`: chạy formal model, static analyzer, CBMC, sanitizer và fuzzer.
- `app.py`: giao diện Streamlit để demo và kiểm chứng trực quan.

## 5. Phương pháp thực hiện

### 5.1. Authentication workflow

Hệ thống người dùng lưu trữ mật khẩu dưới dạng hash PBKDF2-HMAC-SHA256 với salt ngẫu nhiên. Mỗi lần đăng nhập đều kiểm tra:

- tài khoản tồn tại hay không
- mật khẩu đúng hay sai
- số lần thất bại vượt giới hạn hay chưa
- session còn hiệu lực hay không

Nếu người dùng nhập sai số lần vượt ngưỡng, trạng thái tài khoản chuyển sang `LOCKED` để ngăn truy cập tiếp tục.

### 5.2. Email notification workflow

Mô hình email có các trạng thái: `IDLE`, `QUEUED`, `SENT`, `FAILED`. Hệ thống kiểm tra địa chỉ email hợp lệ, xử lý retry nếu gửi thất bại và cập nhật trạng thái theo luồng logic.

### 5.3. Formal model và constraints

Các trạng thái của hệ thống được mô hình hóa bằng Kripke model để biểu thị các trạng thái và các transition. Những ràng buộc như "account locked không được login" hay "password phải đủ dài" được kiểm tra bằng Z3.

### 5.4. C buffer analysis

Dự án có hai phiên bản của hàm `copy_buffer`:

- bản vulnerable: cho phép negative length đi qua điều kiện kiểm tra và gây lỗi khi cast sang `size_t`
- bản safe: kiểm tra rõ `length < 0`, và giới hạn dung lượng source/destination

Sau đó, dự án chạy các bước kiểm tra sau:

- bounded model checking
- GCC static analysis
- CBMC formal verification
- AddressSanitizer / UndefinedBehaviorSanitizer
- deterministic fuzzing

## 6. Kết quả đạt được

Dự án đã đạt được các kết quả chính sau:

- Xây dựng được demo mô phỏng hệ thống LMS với auth và email workflows.
- Tạo được mô hình Kripke và ràng buộc cho hệ thống state-based.
- Phát hiện counterexample trong ví dụ C vulnerable bằng bounded model.
- Chứng minh phiên bản safe không vi phạm ràng buộc trong miền kiểm chứng.
- Chạy được báo cáo phân tích C dưới nhiều công cụ: Z3, GCC, Clang, CBMC, sanitizer, fuzzing.
- Giao diện Streamlit giúp người dùng trực quan quan sát các module và kết quả phân tích.

## 7. Kết luận

Dự án này cho thấy rằng bảo mật phần mềm không chỉ là việc xây dựng logic ứng dụng mà còn cần kiểm tra formal, kiểm thử và phân tích lỗi runtime. Thông qua ví dụ LMS và ví dụ C buffer-copy, đồ án đã thể hiện cách các kỹ thuật kiểm chứng an ninh được áp dụng trong thực tế học thuật và demo.

Nó phù hợp với mục tiêu của một đồ án môn học vì không chỉ kiểm tra logic mà còn minh họa trực quan được các nguyên tắc bảo mật phần mềm về trạng thái, ràng buộc và lỗi bộ nhớ.

## 8. Hạn chế

- Dữ liệu đang lưu trong bộ nhớ, chưa triển khai database thực tế.
- Chưa phải hệ thống production-ready.
- Một số phần phân tích C cần toolchain đầy đủ như CBMC và Clang/ASan/UBSan để đạt hiệu quả tối đa.
- Đây là mô hình demo hướng giáo dục, không thay thế hệ thống bảo mật đầy đủ trong thực tế.
