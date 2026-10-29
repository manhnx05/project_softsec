# BIÊN BẢN KIỂM THỬ

**Dự án:** Project SoftSec - Hệ thống LMS an toàn (mô hình hình thức, phân tích tĩnh/động và fuzzing)
**Mã nguồn:** `https://github.com/manhnx05/project_softsec.git`
**Phiên bản:** 0.1.0
**Ngày lập biên bản:** 30/10/2026
**Người thực hiện:** (điền tên sinh viên thực hiện)
**Người kiểm tra / xác nhận:** (điền tên giảng viên hướng dẫn)

---

## 1. Mục đích và phạm vi

Biên bản này ghi nhận kết quả kiểm thử thực tế của dự án, đối chiếu với **ma trận phòng thủ 7 tầng**:

| Tầng | Lớp phòng thủ | Công cụ / Phương pháp |
|------|----------------|------------------------|
| 1 | Mô hình hình thức | Kripke Structure / FSM (Python) |
| 2 | Kiểm chứng SMT + BMC | Microsoft Z3, mô hình bị chặn giới hạn (bounded model) |
| 3 | Phân tích tĩnh | GCC `-fanalyzer -Wconversion -Wsign-conversion` |
| 4 | Kiểm mô hình giới hạn | CBMC |
| 5 | Phân tích động | AddressSanitizer + UndefinedBehaviorSanitizer |
| 6 | Fuzzing | Black-box CLI, White-box deterministic (XorShift32) |
| 7 | Phòng thủ nhiều lớp & hồi quy | Kịch bản E2E + bộ 65 kiểm thử `pytest` |

Phạm vi: toàn bộ 7 tầng nêu trên và **toàn bộ 65 test** của bộ kiểm thử tự động.

**Tiêu chí đạt:** mỗi tầng có kết quả tường minh `PASS`/`FAIL`/`UNAVAILABLE`; riêng các tầng tìm lỗi cố ý (mô hình lỗ hổng, ASan) được ghi nhận là `FINDING` khi phát hiện đúng lỗi đã dự đoán.

---

## 2. Môi trường kiểm thử

| Thành phần | Giá trị |
|------------|---------|
| Hệ điều hành | Windows (máy trạm) + Docker Desktop (container `gcc:13`, Linux x86-64) |
| Python | 3.13.7 |
| Trình quản lý gói | `uv` (môi trường ảo tách biệt) |
| Trình biên dịch C (host) | GCC MinGW-w64 16.2.0 (không kèm runtime ASan/UBSan) |
| Trình biên dịch C (dynamic) | `gcc:13` trong Docker (Linux, có đầy đủ ASan/UBSan) |
| SMT Solver | Microsoft Z3 (`z3-solver` qua `uv`) |
| Kiểm thử Python | `pytest` 8.x + `pytest-cov` |
| CBMC | Không cài đặt (ghi nhận `UNAVAILABLE`) |

**Tham số cấu hình dùng chung**

- Sức chứa bộ đệm: `BUFFER_COPY_CAPACITY = 16` byte.
- Miền số nguyên có dấu 32-bit: `[-2147483648, 2147483647]`.
- Seed fuzzing: `0x00C0FFEE` = `12648430` (XorShift32, tất định).
- Số vòng fuzzing pipeline: **100**; số vòng mutation C: **10000**.
- Băm mật khẩu: PBKDF2-SHA256, mặc định production `600000` vòng; khi chạy fuzzing hạ xuống `10000` vòng qua biến môi trường `LMS_PASSWORD_HASH_ITERATIONS` để tăng tốc, không ảnh hưởng tới bất biến kiểm thử.

---

## 3. Kết quả tổng hợp theo 7 tầng

| # | Tầng | Kết quả | Ghi chú |
|---|------|---------|---------|
| 1 | Mô hình hình thức (Kripke/FSM) | PASS | 3 test mô hình/đồ thị trạng thái |
| 2 | Z3/SMT + BMC (mô hình bị chặn) | PASS (mô hình an toàn) / FINDING (mô hình lỗ hổng) | Phát hiện đúng phản chứng `length = -1` |
| 3 | GCC Static Analyzer | PASS | Biên dịch sạch có cảnh báo chuyển đổi |
| 4 | CBMC | UNAVAILABLE | Công cụ chưa cài đặt, không tính là đã kiểm chứng |
| 5 | ASan/UBSan | FINDING | Bẫy `negative-size-param` trên ngăn xếp (đúng lỗi dự đoán) |
| 6 | Fuzzing (black-box + white-box + Python) | PASS | 5/5 tầng fuzzing PASS, 0 phát hiện ngoài dự kiến |
| 7 | Kịch bản E2E + bộ 65 test | PASS | 31/31 kịch bản, `pytest` 65 passed |

---

## 4. Chi tiết kết quả theo từng tầng

### 4.1 Tầng 1 - Mô hình hình thức

| Mã | Nội dung | Kết quả |
|----|----------|---------|
| TC-F1 | `test_auth_kripke` - dựng cấu trúc Kripke cho luồng xác thực, kiểm tra trạng thái/độ chuyển tiếp | PASS |
| TC-F2 | `test_email_kripke` - dựng Kripke cho luồng email, khớp 4 cạnh chuyển trạng thái | PASS |
| TC-F3 | `test_buffer_copy_model_has_valid_state_graph` - đồ thị trạng thái mô hình buffer-copy hợp lệ | PASS |

### 4.2 Tầng 2 - Kiểm chứng SMT (Z3) và mô hình bị chặn

| Mã | Nội dung | Kết quả | Bằng chứng |
|----|----------|---------|------------|
| TC-Z1 | Mô hình lỗ hổng - tìm phản chứng | FINDING (đúng dự đoán) | `length = -32`; vết `S0_INPUT -> S1_VALIDATE -> S3_COPY -> S4_DONE` |
| TC-Z2 | Mô hình an toàn - kiểm tra miền giới hạn | PASS | Không có vi phạm trong `length ∈ [-32, 32]`, size ∈ {0,1,8,16} |
| TC-Z3 | Z3 - guard yếu cho phép sao chép sai | FINDING (đúng dự đoán) | `length=-1, source_size=16, destination_capacity=16` |
| TC-Z4 | Z3 - guard an toàn không thừa nhận giá trị sai | PASS | `unsat` trên miền số nguyên 32-bit có dấu đã mô hình hóa |
| TC-Z5 | `test_vulnerable_model_exposes_negative_length_counterexample` | PASS |
| TC-Z6 | `test_safe_model_rejects_invalid_ranges_and_accepts_boundaries` | PASS |
| TC-Z7 | `test_bounded_model_finds_vulnerable_case_and_no_safe_case` | PASS |
| TC-Z8 | `test_model_rejects_unknown_implementation_and_negative_sizes` | PASS |

### 4.3 Tầng 3 - Phân tích tĩnh GCC

| Mã | Đối tượng | Cờ biên dịch | Kết quả |
|----|-----------|--------------|---------|
| TC-S1 | `csrc/vulnerable/buffer_copy.c` | `-std=c11 -Wall -Wextra -Wconversion -Wsign-conversion -fanalyzer` | PASS |
| TC-S2 | `csrc/safe/buffer_copy.c` | `-std=c11 -Wall -Wextra -Wconversion -Wsign-conversion -fanalyzer` | PASS |

### 4.4 Tầng 4 - CBMC

| Mã | Nội dung | Kết quả |
|----|----------|---------|
| TC-B1 | Kiểm mô hình giới hạn bằng CBMC | UNAVAILABLE (CBMC chưa cài đặt) |

Ghi chú: tầng này không đưa ra kết luận đã kiểm chứng; vai trò tương đương được bù bằng mô hình bị chặn ở Tầng 2.

### 4.5 Tầng 5 - Phân tích động (ASan/UBSan)

| Mã | Đối tượng | Đầu vào | Kỳ vọng | Thực tế | Kết quả |
|----|-----------|---------|---------|---------|---------|
| TC-D1 | `vulnerable` (Docker `gcc:13`, ASan+UBSan) | `length = -1` | Báo lỗi bộ nhớ | `ERROR: AddressSanitizer: negative-size-param (size=-1)` trong `memcpy`, khung ngăn xếp của `main` | FINDING |
| TC-D2 | `safe` (Docker `gcc:13`, ASan+UBSan) | `length = -1` | Từ chối | `Copy rejected with code -2.`, exit `2` | PASS |
| TC-D3 | `safe` (Docker `gcc:13`, ASan+UBSan) | `length = 17` | Từ chối | `Copy rejected with code -3.`, exit `2` | PASS |
| TC-D4 | `sanitizer build` (MinGW host) | - | Có thể build | `cannot find -lasan` / `-lubsan` | UNAVAILABLE |

### 4.6 Tầng 6 - Fuzzing

**Lệnh:** `uv run python main.py --fuzz --iterations 100 --seed 12648430`

| Mã | Tầng fuzzing | Số vòng | Kết quả |
|----|--------------|---------|---------|
| TC-U1 | Black-box CLI boundary | 9 ca | PASS 9/9 |
| TC-U2 | White-box deterministic (C) | 100 | PASS, phủ 5/5 lớp đầu vào |
| TC-U3 | Python fuzzing (authentication) | 100 | PASS, 0 phát hiện |
| TC-U4 | Python fuzzing (email) | 100 | PASS, 0 phát hiện |
| TC-U5 | Python fuzzing (email_retry) | 100 | PASS, 0 phát hiện |
| TC-U6 | Deterministic mutation fuzzing (C, `--c-analysis`) | 10000 | PASS |

Phân bố phủ đầu vào của white-box/mutation (seed `12648430`):

| Lớp đầu vào | Mutation (10000) |
|-------------|------------------|
| negative | 2025 |
| zero | 1019 |
| valid_positive | 3318 |
| over_capacity | 1638 |
| integer_extreme | 2000 |

### 4.7 Tầng 7 - Kịch bản E2E và bộ kiểm thử hồi quy

**Kịch bản E2E:** `uv run python main.py --scenarios` -> **31/31 PASS**

- `AUTH-01` … `AUTH-15` (15 kịch bản xác thực)
- `EMAIL-01` … `EMAIL-08` (8 kịch bản email)
- `VER-01` … `VER-07` (7 kịch bản kiểm chứng)
- `E2E-01` (1 kịch bản đầu-cuối)

**Bộ kiểm thử tự động:** `uv run python -m pytest -q --cov=src`

| File kiểm thử | Số test | Nội dung |
|---------------|---------|----------|
| `tests/test_lms.py` | 14 | Xác thực, khóa tài khoản, phiên, băm mật khẩu, email, Kripke |
| `tests/test_c_analysis.py` | 6 | Mô hình C, Z3, báo cáo phân tích |
| `tests/test_fuzz_pipeline.py` | 5 | Pipeline fuzzing, tái lập, xuất báo cáo |
| `tests/test_project_entry.py` | 6 | CLI entry, sinh mã, dashboard Streamlit |
| `tests/test_e2e_scenarios.py` | 4 | Danh mục kịch bản (1 test tham số hóa chạy 31 lần) |
| **Tổng** | **65** | **65 passed** |

Kết quả chi tiết: `65 passed in 141.39s`, độ phủ `TOTAL 78%` (1816 câu lệnh, 404 bỏ qua).

Danh sách test theo file:

- `test_lms.py`: `test_register_and_login`, `test_wrong_password`, `test_account_locked_after_max_attempts`, `test_locked_account_cannot_login`, `test_logout_invalidates_session`, `test_logout_revokes_all_sessions_permanently`, `test_short_password_rejected`, `test_password_hash_uses_unique_salts_and_verifies_password`, `test_password_verification_rejects_malformed_hash`, `test_email_success`, `test_email_retry`, `test_invalid_email`, `test_auth_kripke`, `test_email_kripke`.
- `test_c_analysis.py`: `test_buffer_copy_model_has_valid_state_graph`, `test_vulnerable_model_exposes_negative_length_counterexample`, `test_safe_model_rejects_invalid_ranges_and_accepts_boundaries`, `test_bounded_model_finds_vulnerable_case_and_no_safe_case`, `test_model_rejects_unknown_implementation_and_negative_sizes`, `test_end_to_end_c_analysis_writes_explicit_report`.
- `test_fuzz_pipeline.py`: `test_pipeline_runs_every_fuzz_stage`, `test_pipeline_finds_no_python_invariant_violation`, `test_pipeline_is_reproducible_for_a_fixed_seed`, `test_pipeline_writes_json_markdown_and_html`, `test_pipeline_rejects_invalid_parameters`.
- `test_project_entry.py`: `test_main_help_lists_available_commands`, `test_legacy_demo_entrypoint_imports`, `test_state_generator_renders_spec`, `test_safe_c_generator_emits_canonical_implementation_and_header`, `test_dashboard_actions_store_section_results`, `test_dashboard_runs_fuzzing_and_scenario_tabs`.
- `test_e2e_scenarios.py`: `test_catalogue_exposes_every_declared_scenario`, `test_scenario_ids_are_unique_and_cover_every_family`, `test_each_scenario_declares_and_passes` (31 lần, một lần cho mỗi kịch bản), `test_run_all_scenarios_reports_pass`.

---

## 5. Bằng chứng đính kèm

### 5.1 Nguyên nhân gốc và hệ quả

- Lỗi gốc: **CWE-195** (chuyển đổi sai số nguyên có dấu sang không dấu) - độ dài âm bị ép kiểu `size_t`.
- Hệ quả: **CWE-787** (Out-of-bounds Write) trên **vùng đệm ngăn xếp** `destination` (16 byte) trong `csrc/vulnerable/buffer_copy.c` tại lệnh `memcpy` (dòng 27).

### 5.2 Nhật ký AddressSanitizer (Docker `gcc:13`, đầu vào `length = -1`)

```text
===VULN===
=================================================================
==21==ERROR: AddressSanitizer: negative-size-param: (size=-1)
    #0 ... in __interceptor_memcpy (/usr/local/lib64/libasan.so.8+0x70dd8)
    #1 ... in copy_buffer (/tmp/vuln+0x4012d5)
    #2 ... in main (/tmp/vuln+0x40179c)

Address ... is located in stack of thread T0 at offset 64 in frame
    #0 ... in main (/tmp/vuln+0x401324)

  This frame has 3 object(s):
    [32, 40) 'end' (line 12)
    [64, 80) 'source' (line 10) <== Memory access at offset 64 is inside this variable
    [96, 112) 'destination' (line 11)
SUMMARY: AddressSanitizer: negative-size-param in __interceptor_memcpy
==21==ABORTING
VULN_EXIT=1
===SAFE1===
Copy rejected with code -2.
SAFE_EXIT1=2
===SAFE17===
Copy rejected with code -3.
SAFE_EXIT2=2
```

**Diễn giải:** cả `source` và `destination` đều là mảng cục bộ trên ngăn xếp của `main` (`buffer_copy_cli.c`), nên đây là lỗi ghi vượt biên trên ngăn xếp (**không phải** heap). Bản `safe` chủ động từ chối đúng với mã lỗi `-2` (độ dài âm) và `-3` (vượt sức chứa).

### 5.3 Phản chứng Z3 (guard yếu)

```text
length = -1
source_size = 16
destination_capacity = 16
```

Bản an toàn: truy vấn trả về `unsat` trên miền số nguyên 32-bit có dấu đã mô hình hóa.

### 5.4 Tệp báo cáo sinh tự động

- `CodeSoftSec/reports/fuzzing/latest_report.json` - kết quả fuzzing (100 vòng, seed `12648430`, 5/5 PASS, 409 bước).
- `CodeSoftSec/reports/fuzzing/fuzzing_report.json|.md|.html` - báo cáo fuzzing đa định dạng.
- `CodeSoftSec/reports/c_analysis/latest_report.json` - 12 mục kiểm tra phân tích tĩnh/động.

---

## 6. Tổng kết

| Hạng mục | Số lượng | Kết quả |
|----------|----------|---------|
| Tầng phòng thủ | 7 | 5 PASS, 1 FINDING (đúng dự đoán), 1 UNAVAILABLE |
| Kịch bản E2E | 31 | 31 PASS |
| Test tự động (`pytest`) | 65 | 65 PASS (141.39s, coverage 78%) |
| Fuzzing pipeline | 5 tầng | 5/5 PASS |
| Mutation fuzzing (C) | 10000 | PASS |

**Kết luận:** hệ thống đạt đầy đủ các tiêu chí kiểm thử đã đặt ra. Lỗ hổng CWE-787 trong bản `vulnerable` được phát hiện nhất quán qua nhiều tầng độc lập (mô hình hình thức, Z3, ASan, native run), và bản `safe` chặn thành công mọi đầu vào bất hợp lệ. Tầng CBMC ghi nhận `UNAVAILABLE` do thiếu công cụ; đây là hạn chế về môi trường, không phải lỗi của hệ thống.

---

## 7. Xác nhận

| Vai trò | Họ và tên | Chữ ký | Ngày |
|---------|-----------|--------|------|
| Người thực hiện | | | |
| Người kiểm tra | | | |
