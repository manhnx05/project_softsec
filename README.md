# LMS End-to-End Software Security

Dự án này là một mô phỏng giáo dục về bảo mật phần mềm dành cho hệ thống LMS. Nó kết hợp các khía cạnh quan trọng của an ninh ứng dụng: xác thực người dùng, truyền thông báo email, kiểm chứng ràng buộc, mô hình Kripke, phân tích trạng thái, và kiểm tra lỗi bộ nhớ trong mã C.

Mục tiêu chính của dự án là minh họa cách các kỹ thuật kiểm chứng và phân tích an ninh có thể được áp dụng trong một hệ thống học tập, từ mô hình logic cho đến ví dụ C có lỗi và các giải pháp kiểm tra.

## 1. Mục tiêu dự án

- Mô phỏng quy trình xác thực tài khoản LMS.
- Mô tả luồng email thông báo với trạng thái retry và failure handling.
- Dùng mô hình Kripke và constraints để biểu diễn trạng thái hệ thống.
- Chứng minh cách tìm counterexample trong ví dụ buffer-copy C.
- Kiểm tra trên Python và C bằng các công cụ phù hợp như Z3, GCC, Clang, CBMC, và sanitizers.

## 2. Công nghệ sử dụng

- Python 3.11+
- Streamlit cho giao diện demo
- Z3 SMT Solver cho verification của ràng buộc
- PyVis / NetworkX cho mô hình Kripke
- PyYAML cho đọc spec YAML
- GCC / Clang cho kiểm tra mã C
- CBMC cho formal verification
- ASan / UBSan cho phát hiện lỗi runtime trong C

## 3. Cài đặt và chạy từng phần

### Chuẩn bị môi trường

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
```

Tất cả phụ thuộc được khai báo một nơi duy nhất trong `pyproject.toml` (bao gồm cả công cụ kiểm thử và phân tích tĩnh).

Các lệnh dưới đây chạy từ thư mục gốc của dự án. Nếu `.venv` đã tồn tại, chỉ cần kích hoạt lại bằng `source .venv/bin/activate`.

### Chạy giao diện

```bash
python main.py --app
```

Mở URL Streamlit được in ra terminal, thường là `http://localhost:8501`.

- **Functions:** chọn Authentication hoặc EmailNotification, bấm **Run function scenario** để chạy các kịch bản đăng nhập thành công, khóa tài khoản/đăng xuất, gửi email, retry và vượt giới hạn retry.
- **Parameters:** sửa giá trị trong form, bấm **Validate parameters** để xem PASS/FAIL theo kiểu và giới hạn.
- **States:** chọn function, bấm **Analyze state transitions** để xem bảng state/transition và state không reachable.
- **Constraints:** chọn Authentication hoặc Email, nhập dữ liệu rồi bấm nút kiểm tra để xem kết quả từng rule. `SAT` nghĩa là có nghiệm, không phải chứng minh mọi yêu cầu với mọi đầu vào.
- **Kripke:** bấm **Build and validate Kripke model** để xem sơ đồ ngay trên giao diện, trạng thái khởi đầu, mô tả/mệnh đề của từng state, cùng event và guard của transition; có thể tải HTML.
- **Code Generation:** sinh enum Python hoặc bấm **Generate safe C buffer-copy code** để xuất implementation C an toàn và header trong `generated/`, xem source và tải file.
- **Static Testing:** chạy Ruff và mypy cho Python. Tab C Security Analysis phân biệt rõ GCC diagnostics, CBMC BMC, Z3/SMT và ASan/UBSan; BMC/SMT là kiểm chứng trên mô hình/miền đã nêu, ASan/UBSan kiểm tra khi thực thi.
- **Dynamic Testing:** chạy pytest hoặc pytest kèm coverage.
- **Report:** tổng hợp kết quả đã chạy trong phiên dashboard hiện tại và tải JSON.
- **C Security Analysis:** chọn số vòng fuzz/seed rồi bấm **Run end-to-end C analysis**. Báo cáo ghi bounds, seed corpus, input-class coverage, black-box kiểm tra CLI ở biên và white-box fuzz trực tiếp có timeout để phát hiện crash/hang. Báo cáo chi tiết có thể tải JSON.
- **Fuzzing:** dựng luồng fuzzing hoàn chỉnh (black-box CLI, white-box C, property fuzzing Python) với seed tái lập. Tab hiển thị sơ đồ luồng, bảng coverage và seed data, danh sách findings, và cho tải báo cáo HTML tự chứa/JSON/Markdown.
- **E2E Scenarios:** liệt kê danh mục kịch bản End-to-End của LMS; bấm **Run all E2E scenarios** để thực thi tất cả và xem bằng chứng PASS/FAIL kèm tải JSON.

### Chạy từng nhóm test

```bash
# Authentication, email và Kripke
python -m pytest tests/test_lms.py -q

# Lọc một nhóm test
python -m pytest tests/test_lms.py -q -k "login or password or logout"
python -m pytest tests/test_lms.py -q -k email
python -m pytest tests/test_lms.py -q -k kripke

# Phân tích C
python -m pytest tests/test_c_analysis.py -q

# Fuzzing pipeline và kịch bản E2E
python -m pytest tests/test_fuzz_pipeline.py tests/test_e2e_scenarios.py -q

# Toàn bộ test suite
python main.py --test
```

### Chạy demo mô hình và sinh code

```bash
python -m src.main
```

Lệnh này chạy demo auth/email, kiểm tra constraints, in Kripke model và sinh `generated/auth_states.py` cùng `generated/email_states.py`.

### Chạy static analysis và coverage

```bash
ruff check src
mypy src
python -m pytest --cov=src --cov-report=term-missing
```

Exit code khác `0` hoặc thông báo lỗi cho biết bước kiểm tra chưa đạt; dashboard cũng hiển thị stdout/stderr của từng công cụ.

### Chạy phân tích C và đọc report

```bash
python main.py --c-analysis
```

Muốn đặt số vòng fuzz và seed cụ thể:

```bash
python -c "from src.c_analysis.runner import run_c_analysis; report = run_c_analysis(iterations=1000, seed=12648430); print(report.to_dict())"
```

Report JSON mặc định nằm ở `reports/c_analysis/latest_report.json`. `FINDING` trên bản vulnerable là kết quả mong đợi của demo; `UNAVAILABLE` nghĩa là công cụ tùy chọn như CBMC chưa có trong `PATH`, không được tính là `PASS`.

### Chạy fuzzing pipeline và kịch bản E2E

```bash
# Fuzzing: black-box CLI, white-box C, property fuzzing Python
python main.py --fuzz --iterations 2000 --seed 12648430

# Danh mục kịch bản End-to-End của LMS
python main.py --scenarios
```

Fuzzing ghi `reports/fuzzing/latest_report.json` cùng `fuzzing_report.json`, `fuzzing_report.md` và `fuzzing_report.html` (HTML tự chứa, sơ đồ luồng là SVG inline). Cùng một `seed` cho ra cùng corpus và cùng coverage; mỗi stage báo cáo seed data, coverage theo input class và findings. Lệnh trả exit code `1` nếu có `FINDING`/`ERROR`. `--scenarios` thực thi toàn bộ kịch bản E2E và in `PASS`/`FAIL` kèm bằng chứng.

### Xem lệnh CLI

```bash
python main.py --list
```

## 4. Cấu trúc thư mục chính

- `app.py`: giao diện Streamlit chính
- `main.py`: entry point CLI của dự án
- `src/modules/`: các module nghiệp vụ: authentication, email notification
- `src/verification/`: ràng buộc và mô hình Kripke
- `src/specification/`: loader spec và schema
- `src/c_analysis/`: mô hình và runner cho phân tích C
- `src/testing/`: fuzzing (C và Python), pipeline fuzzing, và danh mục kịch bản E2E
- `csrc/`: ví dụ C có lỗi và sửa lỗi
- `tests/`: các bài test kiểm thử logic và analysis workflow
- `docs/`: tài liệu mô tả, sơ đồ, báo cáo

## 5. Phân tích C buffer-copy

Thư mục `csrc/` chứa các ví dụ sau:

- `vulnerable/buffer_copy.c`: phiên bản mục đích có lỗi `memcpy` với length âm
- `safe/buffer_copy.c`: phiên bản sửa lỗi bằng kiểm tra âm và out-of-range
- `harness/cbmc_buffer_copy_harness.c`: harness phục vụ CBMC
- `cli/buffer_copy_cli.c`: CLI dùng để chạy native checks
- `include/buffer_copy.h`: định nghĩa hằng số và return codes

Phần này minh họa rõ ràng cách lỗi memory safety xuất hiện và cách các công cụ kiểm chứng phát hiện hậu quả. Mô hình bounded check kiểm tra một miền giá trị từ -32 đến 32, cùng với kích thước buffer tối đa 16 byte, nên nó là bằng chứng hữu ích nhưng không phải là chứng minh toàn bộ mọi trường hợp trong C.

## 6. Kết quả kiểm thử hiện tại

Dự án đang được kiểm chứng bằng test suite Python, và các module chính đều chạy đúng trong môi trường khởi tạo. Cụ thể:

- Unit tests: Pass
- Streamlit UI: render được
- Z3 model: phát hiện counterexample đúng với thiết kế
- CBMC: chạy và phát hiện lỗi trên phiên bản vulnerable
- Sanitizer: Clang + ASan/UBSan phát hiện lỗi runtime của ví dụ vulnerable

## 7. Giới hạn và lưu ý

- Đây là dự án giáo dục, không phải hệ thống auth production-ready.
- Dữ liệu hiện nay lưu trong memory, không có database, session persistence hay bảo mật vận hành đầy đủ.
- CBMC và sanitizer phụ thuộc vào môi trường toolchain; khi thiếu công cụ, hệ thống báo `UNAVAILABLE` thay vì giả định pass.
- Phân tích C là bounded và demo-oriented, không thay thế cho review bảo mật chuyên nghiệp.

## 8. Ý nghĩa học tập

Dự án này phù hợp cho môn học về an ninh phần mềm vì nó kết hợp nhiều khía cạnh:

- formal verification
- model checking
- security testing
- runtime sanitizers
- state-based modeling
- automated validation

Nó không chỉ minh họa lỗi bảo mật mà còn cho thấy cách xây dựng một pipeline kiểm chứng có hệ thống từ mô hình đến thực thi.
