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
| Hệ điều hành | Windows (máy trạm) + Docker Desktop (container `gcc:13` cho ASan/UBSan, `ubuntu:24.04` cho CBMC, Linux x86-64) |
| Python | 3.13.7 |
| Trình quản lý gói | `uv` (môi trường ảo tách biệt) |
| Trình biên dịch C (host) | GCC MinGW-w64 16.2.0 (không kèm runtime ASan/UBSan) |
| Trình biên dịch C (dynamic) | `gcc:13` trong Docker (Linux, có đầy đủ ASan/UBSan) |
| SMT Solver | Microsoft Z3 (`z3-solver` qua `uv`) |
| Kiểm thử Python | `pytest` 8.x + `pytest-cov` |
| CBMC | 5.95.1 (gói `cbmc` trên container `ubuntu:24.04`); bản Windows chỉ có front-end MSVC `goto-cl` nên không parse được header MinGW |

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
| 4 | CBMC | PASS (mô hình an toàn) / FINDING (mô hình lỗ hổng) | Phản chứng `length = -2147483648` tại `buffer_copy.c:27` |
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

**Công cụ:** CBMC 5.95.1 trong container `ubuntu:24.04` (Docker), chạy đúng lệnh của `src/c_analysis/runner.py`.

**Lệnh:**

```text
docker run --rm -v <repo>:/work -w /work ubuntu:24.04 bash -c \
  "apt-get install -y cbmc && \
   cbmc csrc/<impl>/buffer_copy.c csrc/harness/cbmc_buffer_copy_harness.c \
        -I csrc/include --bounds-check --pointer-check --signed-overflow-check --trace"
```

Harness `csrc/harness/cbmc_buffer_copy_harness.c` khai báo hai mảng ngăn xếp 16 byte (`source`, `destination`) và dùng `nondet_int()` cho `length`, để bộ kiểm mô hình tự do chọn độ dài.

| Mã | Đối tượng | VCC | Vi phạm | Kết luận | Kết quả |
|----|-----------|-----|---------|----------|---------|
| TC-B1 | `csrc/vulnerable/buffer_copy.c` | 29 | `2 of 29 failed` (2 vòng lặp) | `VERIFICATION FAILED` (exit `10`) | FINDING (đúng dự đoán) |
| TC-B2 | `csrc/safe/buffer_copy.c` | 29 | `0 of 29 failed` (1 vòng lặp) | `VERIFICATION SUCCESSFUL` (exit `0`) | PASS |

**Chi tiết vi phạm ở bản `vulnerable` (3 điều kiện tiên quyết của `memcpy` tại dòng 27):**

| Property | Dòng | Kết quả |
|----------|------|---------|
| `copy_buffer.precondition_instance.1` — memcpy src/dst overlap | 27 | SUCCESS |
| `copy_buffer.precondition_instance.2` — memcpy source region readable | 27 | **FAILURE** |
| `copy_buffer.precondition_instance.3` — memcpy destination region writeable | 27 | **FAILURE** |

Phản chứng CBMC tự chọn: `length = -2147483648` (`INT_MIN`, nhị phân `1000 0000 ...`), với `source_size = destination_capacity = 16`.

Ở bản `safe`, cả 3 property tương ứng tại dòng 28 đều `SUCCESS` và không có vi phạm nào trên toàn bộ 29 VCC.

Ghi chú: bản CBMC Windows chỉ phát hành front-end MSVC (`goto-cl`) nên không phân tích được header MinGW trên máy trạm; do đó tầng này được chạy trong container Linux tương tự cách chạy ASan (Tầng 5).

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

Kết quả chi tiết: `65 passed in 209.84s`, độ phủ `TOTAL 78%` (1816 câu lệnh, 404 bỏ qua).

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
==22==ERROR: AddressSanitizer: negative-size-param: (size=-1)
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
==22==ABORTING
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

### 5.4 Nhật ký CBMC (Docker `ubuntu:24.04`, CBMC 5.95.1)

Bằng chứng thô: [cbmc_vulnerable.log](file:///d:/Study/SoftSecProject/CodeSoftSec/reports/cbmc/cbmc_vulnerable.log), [cbmc_safe.log](file:///d:/Study/SoftSecProject/CodeSoftSec/reports/cbmc/cbmc_safe.log), [summary.txt](file:///d:/Study/SoftSecProject/CodeSoftSec/reports/cbmc/summary.txt).

```text
=== CBMC VERSION ===
5.95.1 (cbmc-5.95.1)

=== VULNERABLE (csrc/vulnerable/buffer_copy.c) ===
Generating GOTO Program ... Running Bounded Model Checking ...
Generated 29 VCC(s), 2 remaining after simplification
SAT checker: instance is SATISFIABLE

** Results:
csrc/vulnerable/buffer_copy.c function copy_buffer
[copy_buffer.precondition_instance.1] line 27 memcpy src/dst overlap: SUCCESS
[copy_buffer.precondition_instance.2] line 27 memcpy source region readable: FAILURE
[copy_buffer.precondition_instance.3] line 27 memcpy destination region writeable: FAILURE

Violated property:
  file csrc/vulnerable/buffer_copy.c function copy_buffer line 27 thread 0
  memcpy source region readable
  R_OK((const void *)source, (size_t)length)

Violated property:
  file csrc/vulnerable/buffer_copy.c function copy_buffer line 27 thread 0
  memcpy destination region writeable
  W_OK((void *)destination, (size_t)length)

Phản chứng (rút gọn từ trace):
  length=-2147483648 (10000000 00000000 00000000 00000000)
  source_size=sizeof(unsigned char [16]) = 16
  destination_capacity=sizeof(unsigned char [16]) = 16

** 2 of 29 failed (2 iterations)
VERIFICATION FAILED
VULN_EXIT=10

=== SAFE (csrc/safe/buffer_copy.c) ===
** Results:
csrc/safe/buffer_copy.c function copy_buffer
[copy_buffer.precondition_instance.1] line 28 memcpy src/dst overlap: SUCCESS
[copy_buffer.precondition_instance.2] line 28 memcpy source region readable: SUCCESS
[copy_buffer.precondition_instance.3] line 28 memcpy destination region writeable: SUCCESS

** 0 of 29 failed (1 iterations)
VERIFICATION SUCCESSFUL
SAFE_EXIT=0
```

**Diễn giải:** CBMC tự do chọn `length = -2147483648` (giá trị `INT_MIN`). Do guard yếu chỉ kiểm tra cận trên `length > (int)destination_capacity`, độ dài âm lọt qua và bị ép kiểu thành `size_t` cực lớn, khiến vùng đọc/ghi của `memcpy` vượt khỏi hai mảng ngăn xếp 16 byte - khớp chính xác phản chứng Z3 (`length = -1`) và bẫy ASan (`negative-size-param`) ở các tầng khác, qua đó củng cố kết luận CWE-787.

### 5.5 Tệp báo cáo sinh tự động

- `CodeSoftSec/reports/fuzzing/latest_report.json` - kết quả fuzzing (100 vòng, seed `12648430`, 5/5 PASS, 409 bước).
- `CodeSoftSec/reports/fuzzing/fuzzing_report.json|.md|.html` - báo cáo fuzzing đa định dạng.
- `CodeSoftSec/reports/c_analysis/latest_report.json` - 12 mục kiểm tra phân tích tĩnh/động.
- `CodeSoftSec/reports/cbmc/cbmc_vulnerable.log`, `cbmc_safe.log`, `summary.txt` - nhật ký CBMC thô (Tầng 4).

> Nhật ký thô đầy đủ của cả 7 tầng (pytest, E2E, phân tích C, CBMC, ASan/UBSan, fuzzing) được đính kèm nguyên văn ở **Phụ lục A** cuối biên bản.

---

## 6. Tổng kết

| Hạng mục | Số lượng | Kết quả |
|----------|----------|---------|
| Tầng phòng thủ | 7 | 6 PASS, 1 FINDING (đúng dự đoán) |
| Kịch bản E2E | 31 | 31 PASS |
| Test tự động (`pytest`) | 65 | 65 PASS (209.84s, coverage 78%) |
| Fuzzing pipeline | 5 tầng | 5/5 PASS |
| Mutation fuzzing (C) | 10000 | PASS |

**Kết luận:** hệ thống đạt đầy đủ các tiêu chí kiểm thử đã đặt ra. Lỗ hổng CWE-787 trong bản `vulnerable` được phát hiện nhất quán qua nhiều tầng độc lập (mô hình hình thức, Z3/SMT, CBMC, ASan, native run): CBMC tìm phản chứng `length = -2147483648` tại `buffer_copy.c:27`, Z3 tìm `length = -1`, ASan bẫy `negative-size-param` - cả ba cùng chỉ về một điểm lỗi, và bản `safe` chặn thành công mọi đầu vào bất hợp lệ ở tất cả các tầng.

---

## 7. Xác nhận

| Vai trò | Họ và tên | Chữ ký | Ngày |
|---------|-----------|--------|------|
| Người thực hiện | | | |
| Người kiểm tra | | | |

---

## Phụ lục A - Nhật ký kiểm thử đầy đủ

Phụ lục ghi lại nguyên văn nhật ký thô của lần chạy ngày 30/10/2026. File gốc nằm trong `CodeSoftSec/reports/logs/` và `CodeSoftSec/reports/cbmc/`. Nội dung dưới đây giữ nguyên định dạng đầu ra của công cụ.

### A.1 Danh mục bộ 65 kiểm thử tự động

Lệnh: `uv run python -m pytest --collect-only -q`

```text
tests/test_c_analysis.py::test_buffer_copy_model_has_valid_state_graph
tests/test_c_analysis.py::test_vulnerable_model_exposes_negative_length_counterexample
tests/test_c_analysis.py::test_safe_model_rejects_invalid_ranges_and_accepts_boundaries
tests/test_c_analysis.py::test_bounded_model_finds_vulnerable_case_and_no_safe_case
tests/test_c_analysis.py::test_model_rejects_unknown_implementation_and_negative_sizes
tests/test_c_analysis.py::test_end_to_end_c_analysis_writes_explicit_report
tests/test_e2e_scenarios.py::test_catalogue_exposes_every_declared_scenario
tests/test_e2e_scenarios.py::test_scenario_ids_are_unique_and_cover_every_family
tests/test_e2e_scenarios.py::test_each_scenario_declares_and_passes[AUTH-01]
tests/test_e2e_scenarios.py::test_each_scenario_declares_and_passes[AUTH-02]
tests/test_e2e_scenarios.py::test_each_scenario_declares_and_passes[AUTH-03]
tests/test_e2e_scenarios.py::test_each_scenario_declares_and_passes[AUTH-04]
tests/test_e2e_scenarios.py::test_each_scenario_declares_and_passes[AUTH-05]
tests/test_e2e_scenarios.py::test_each_scenario_declares_and_passes[AUTH-06]
tests/test_e2e_scenarios.py::test_each_scenario_declares_and_passes[AUTH-07]
tests/test_e2e_scenarios.py::test_each_scenario_declares_and_passes[AUTH-08]
tests/test_e2e_scenarios.py::test_each_scenario_declares_and_passes[AUTH-09]
tests/test_e2e_scenarios.py::test_each_scenario_declares_and_passes[AUTH-10]
tests/test_e2e_scenarios.py::test_each_scenario_declares_and_passes[AUTH-11]
tests/test_e2e_scenarios.py::test_each_scenario_declares_and_passes[AUTH-12]
tests/test_e2e_scenarios.py::test_each_scenario_declares_and_passes[AUTH-13]
tests/test_e2e_scenarios.py::test_each_scenario_declares_and_passes[AUTH-14]
tests/test_e2e_scenarios.py::test_each_scenario_declares_and_passes[AUTH-15]
tests/test_e2e_scenarios.py::test_each_scenario_declares_and_passes[EMAIL-01]
tests/test_e2e_scenarios.py::test_each_scenario_declares_and_passes[EMAIL-02]
tests/test_e2e_scenarios.py::test_each_scenario_declares_and_passes[EMAIL-03]
tests/test_e2e_scenarios.py::test_each_scenario_declares_and_passes[EMAIL-04]
tests/test_e2e_scenarios.py::test_each_scenario_declares_and_passes[EMAIL-05]
tests/test_e2e_scenarios.py::test_each_scenario_declares_and_passes[EMAIL-06]
tests/test_e2e_scenarios.py::test_each_scenario_declares_and_passes[EMAIL-07]
tests/test_e2e_scenarios.py::test_each_scenario_declares_and_passes[EMAIL-08]
tests/test_e2e_scenarios.py::test_each_scenario_declares_and_passes[VER-01]
tests/test_e2e_scenarios.py::test_each_scenario_declares_and_passes[VER-02]
tests/test_e2e_scenarios.py::test_each_scenario_declares_and_passes[VER-03]
tests/test_e2e_scenarios.py::test_each_scenario_declares_and_passes[VER-04]
tests/test_e2e_scenarios.py::test_each_scenario_declares_and_passes[VER-05]
tests/test_e2e_scenarios.py::test_each_scenario_declares_and_passes[VER-06]
tests/test_e2e_scenarios.py::test_each_scenario_declares_and_passes[VER-07]
tests/test_e2e_scenarios.py::test_each_scenario_declares_and_passes[E2E-01]
tests/test_e2e_scenarios.py::test_run_all_scenarios_reports_pass
tests/test_fuzz_pipeline.py::test_pipeline_runs_every_fuzz_stage
tests/test_fuzz_pipeline.py::test_pipeline_finds_no_python_invariant_violation
tests/test_fuzz_pipeline.py::test_pipeline_is_reproducible_for_a_fixed_seed
tests/test_fuzz_pipeline.py::test_pipeline_writes_json_markdown_and_html
tests/test_fuzz_pipeline.py::test_pipeline_rejects_invalid_parameters
tests/test_lms.py::test_register_and_login
tests/test_lms.py::test_wrong_password
tests/test_lms.py::test_account_locked_after_max_attempts
tests/test_lms.py::test_locked_account_cannot_login
tests/test_lms.py::test_logout_invalidates_session
tests/test_lms.py::test_logout_revokes_all_sessions_permanently
tests/test_lms.py::test_short_password_rejected
tests/test_lms.py::test_password_hash_uses_unique_salts_and_verifies_password
tests/test_lms.py::test_password_verification_rejects_malformed_hash
tests/test_lms.py::test_email_success
tests/test_lms.py::test_email_retry
tests/test_lms.py::test_invalid_email
tests/test_lms.py::test_auth_kripke
tests/test_lms.py::test_email_kripke
tests/test_project_entry.py::test_main_help_lists_available_commands
tests/test_project_entry.py::test_legacy_demo_entrypoint_imports
tests/test_project_entry.py::test_state_generator_renders_spec
tests/test_project_entry.py::test_safe_c_generator_emits_canonical_implementation_and_header
tests/test_project_entry.py::test_dashboard_actions_store_section_results
tests/test_project_entry.py::test_dashboard_runs_fuzzing_and_scenario_tabs

65 tests collected in 0.88s
```

### A.2 Kết quả chạy đầy đủ 65 kiểm thử kèm độ phủ

Lệnh: `uv run python -m pytest -q --cov=src`

```text
.................................................................        [100%]
=============================== tests coverage ================================
_______________ coverage: platform win32, python 3.13.7-final-0 _______________

Name                                Stmts   Miss  Cover
-------------------------------------------------------
src\__init__.py                         0      0   100%
src\c_analysis\__init__.py              2      0   100%
src\c_analysis\model.py                56      6    89%
src\c_analysis\runner.py              330    110    67%
src\constraints\z3_solver.py           41      7    83%
src\generation\__init__.py              0      0   100%
src\generation\generator.py            74     15    80%
src\generation\verification.py         91     13    86%
src\kripke\builder.py                  12      0   100%
src\kripke\model.py                    37      5    86%
src\kripke\visualizer.py               21      7    67%
src\main.py                            67     52    22%
src\models\__init__.py                  2      0   100%
src\models\states.py                   11      0   100%
src\modules\__init__.py                 0      0   100%
src\modules\authentication.py         120      7    94%
src\modules\email_notification.py      56      1    98%
src\specification\__init__.py           0      0   100%
src\specification\loader.py            18      2    89%
src\specification\schemas.py           29      0   100%
src\state_machine\__init__.py           8      8     0%
src\state_machine\machine.py           22     22     0%
src\state_machine\state.py              8      8     0%
src\state_machine\transition.py         9      9     0%
src\testing\__init__.py                 0      0   100%
src\testing\coverage.py                 0      0   100%
src\testing\dynamic.py                 24     15    38%
src\testing\fuzz_pipeline.py          129     15    88%
src\testing\fuzzing.py                121     23    81%
src\testing\fuzzing_report.py         126      4    97%
src\testing\scenarios.py              247     14    94%
src\testing\static.py                  48     33    31%
src\utils\__init__.py                   0      0   100%
src\utils\logger.py                     4      4     0%
src\verification\__init__.py            0      0   100%
src\verification\bmc.py                37      6    84%
src\verification\constraints.py        22      3    86%
src\verification\kripke.py             44     15    66%
-------------------------------------------------------
TOTAL                                1816    404    78%
65 passed in 209.84s (0:03:29)
```

### A.3 Kịch bản E2E (31/31 PASS)

Lệnh: `uv run python main.py --scenarios`

```text
[PASS] AUTH-01: Đăng ký rồi đăng nhập hợp lệ
[PASS] AUTH-02: Sai mật khẩu → LOGIN_FAILED
[PASS] AUTH-03: Khoá tài khoản sau max_attempts
[PASS] AUTH-04: Tài khoản LOCKED từ chối cả mật khẩu đúng
[PASS] AUTH-05: Logout vô hiệu hoá session hiện tại
[PASS] AUTH-06: Logout thu hồi toàn bộ session của user
[PASS] AUTH-07: Mật khẩu ngắn hơn min_password_length bị từ chối
[PASS] AUTH-08: Username trùng bị từ chối
[PASS] AUTH-09: User không tồn tại không tạo session
[PASS] AUTH-10: Session hết hạn không xác thực được
[PASS] AUTH-11: reset_lock mở khoá và cho đăng nhập lại
[PASS] AUTH-12: Hash mật khẩu có salt ngẫu nhiên
[PASS] AUTH-13: Hash có tham số yếu bị từ chối
[PASS] AUTH-14: Ràng buộc auth đúng sau khi đăng nhập
[PASS] AUTH-15: Ràng buộc phát hiện LOCKED nhưng vẫn cho login
[PASS] EMAIL-01: Tạo và gửi notification thành công
[PASS] EMAIL-02: Recipient không hợp lệ bị từ chối
[PASS] EMAIL-03: Lỗi tạm thời rồi retry thành công
[PASS] EMAIL-04: Vượt retry limit → FAILED
[PASS] EMAIL-05: Gửi notification không tồn tại bị từ chối
[PASS] EMAIL-06: Gửi lại notification đã SENT là idempotent
[PASS] EMAIL-07: Ràng buộc email đúng khi đã SENT
[PASS] EMAIL-08: Ràng buộc phát hiện retry vượt max_retry
[PASS] VER-01: Kripke Authentication hợp lệ và mọi state đều reachable
[PASS] VER-02: Kripke EmailNotification hợp lệ và mọi state đều reachable
[PASS] VER-03: Z3 chứng minh policy 'LOCKED không được login' (UNSAT)
[PASS] VER-04: BMC chứng minh LOCKED reachable từ LOGGED_OUT (SAT)
[PASS] VER-05: Mã sinh ra khớp state trong spec
[PASS] VER-06: Mô hình C an toàn không có counterexample
[PASS] VER-07: Mô hình C lỗi có counterexample
[PASS] E2E-01: Hành trình LMS: đăng ký → đăng nhập → gửi email → logout
31/31 LMS end-to-end scenarios passed
```

### A.4 Phân tích C (mô hình bị chặn, Z3/SMT, GCC, black-box, mutation)

Lệnh: `uv run python main.py --c-analysis` (xuất JSON đầy đủ; biến môi trường `LMS_PASSWORD_HASH_ITERATIONS=10000` chỉ để tăng tốc vòng mutation, không ảnh hưởng bất biến kiểm thử)

```text
{'generated_at': '2026-10-30T04:38:12.881230+00:00', 'checks': [{'name': 'Vulnerable model counterexample', 'status': 'FINDING', 'summary': 'Found length=-32: the vulnerable guard allows an invalid copy.', 'command': '', 'details': 'Trace: S0_INPUT -> S1_VALIDATE -> S3_COPY -> S4_DONE\nViolations: negative length is converted to an unsigned size\nBounded lengths: -32 through 32; source and destination sizes from 0, 1, 8, and 16.'}, {'name': 'Safe model bounded check', 'status': 'PASS', 'summary': 'No safety-constraint violation found in the bounded domain.', 'command': '', 'details': 'Checked lengths -32 through 32 and sizes 0, 1, 8, and 16. This is bounded evidence, not a proof for every possible C execution.'}, {'name': 'Z3 vulnerable guard counterexample', 'status': 'FINDING', 'summary': 'Z3 found an invalid copy admitted by the vulnerable guard.', 'command': '', 'details': 'length=-1, source_size=16, destination_capacity=16\nFixed harness capacity: 16 bytes per buffer.\nQuery: signed length == -1 AND length <= destination capacity AND (length < 0 OR length > source size OR length > destination capacity).'}, {'name': 'Z3 safe guard verification', 'status': 'PASS', 'summary': 'Z3 proved the safe guard admits no invalid length in the modeled 32-bit signed-integer and buffer-size domain.', 'command': '', 'details': 'SMT verifies the modeled guard conditions, not the compiled C binary or pointer behavior.'}, {'name': 'GCC static analysis (vulnerable)', 'status': 'PASS', 'summary': 'GCC compiled the vulnerable implementation with warnings and analyzer checks enabled.', 'command': "'C:\\msys64\\mingw64\\bin\\gcc.EXE' -std=c11 -Wall -Wextra -Wconversion -Wsign-conversion -fanalyzer -I 'D:\\Study\\SoftSecProject\\CodeSoftSec\\csrc\\include' -c 'D:\\Study\\SoftSecProject\\CodeSoftSec\\csrc\\vulnerable\\buffer_copy.c' -o 'C:\\Users\\ADMIN\\AppData\\Local\\Temp\\lms-c-analysis-le3tnmlp\\vulnerable.o'", 'details': ''}, {'name': 'GCC static analysis (safe)', 'status': 'PASS', 'summary': 'GCC compiled the safe implementation with warnings and analyzer checks enabled.', 'command': "'C:\\msys64\\mingw64\\bin\\gcc.EXE' -std=c11 -Wall -Wextra -Wconversion -Wsign-conversion -fanalyzer -I 'D:\\Study\\SoftSecProject\\CodeSoftSec\\csrc\\include' -c 'D:\\Study\\SoftSecProject\\CodeSoftSec\\csrc\\safe\\buffer_copy.c' -o 'C:\\Users\\ADMIN\\AppData\\Local\\Temp\\lms-c-analysis-le3tnmlp\\safe.o'", 'details': ''}, {'name': 'CBMC bounded model checking', 'status': 'UNAVAILABLE', 'summary': 'CBMC is not installed. The bounded Python model and GCC checks still ran; no CBMC result is claimed.', 'command': '', 'details': ''}, {'name': 'Sanitizer build (vulnerable)', 'status': 'UNAVAILABLE', 'summary': 'The installed compiler does not provide the required sanitizer runtime.', 'command': "'C:\\msys64\\mingw64\\bin\\gcc.EXE' -std=c11 -Wall -Wextra -Wconversion -Wsign-conversion -I 'D:\\Study\\SoftSecProject\\CodeSoftSec\\csrc\\include' -fsanitize=address,undefined -fno-omit-frame-pointer 'D:\\Study\\SoftSecProject\\CodeSoftSec\\csrc\\vulnerable\\buffer_copy.c' 'D:\\Study\\SoftSecProject\\CodeSoftSec\\csrc\\cli\\buffer_copy_cli.c' -o 'C:\\Users\\ADMIN\\AppData\\Local\\Temp\\lms-c-analysis-le3tnmlp\\buffer_copy_vulnerable.exe'", 'details': 'C:/msys64/mingw64/bin/../lib/gcc/x86_64-w64-mingw32/16.2.0/../../../../x86_64-w64-mingw32/bin/ld.exe: cannot find -lasan: No such file or directory\nC:/msys64/mingw64/bin/../lib/gcc/x86_64-w64-mingw32/16.2.0/../../../../x86_64-w64-mingw32/bin/ld.exe: cannot find -lubsan: No such file or directory\ncollect2.exe: error: ld returned 1 exit status'}, {'name': 'Sanitizer build (safe)', 'status': 'UNAVAILABLE', 'summary': 'The installed compiler does not provide the required sanitizer runtime.', 'command': "'C:\\msys64\\mingw64\\bin\\gcc.EXE' -std=c11 -Wall -Wextra -Wconversion -Wsign-conversion -I 'D:\\Study\\SoftSecProject\\CodeSoftSec\\csrc\\include' -fsanitize=address,undefined -fno-omit-frame-pointer 'D:\\Study\\SoftSecProject\\CodeSoftSec\\csrc\\safe\\buffer_copy.c' 'D:\\Study\\SoftSecProject\\CodeSoftSec\\csrc\\cli\\buffer_copy_cli.c' -o 'C:\\Users\\ADMIN\\AppData\\Local\\Temp\\lms-c-analysis-le3tnmlp\\buffer_copy_safe.exe'", 'details': 'C:/msys64/mingw64/bin/../lib/gcc/x86_64-w64-mingw32/16.2.0/../../../../x86_64-w64-mingw32/bin/ld.exe: cannot find -lasan: No such file or directory\nC:/msys64/mingw64/bin/../lib/gcc/x86_64-w64-mingw32/16.2.0/../../../../x86_64-w64-mingw32/bin/ld.exe: cannot find -lubsan: No such file or directory\ncollect2.exe: error: ld returned 1 exit status'}, {'name': 'Native dynamic boundary tests', 'status': 'FINDING', 'summary': 'The vulnerable binary failed on a negative length while the safe binary rejected invalid inputs and accepted valid boundaries. These native runs are not sanitizer-instrumented.', 'command': '', 'details': 'vulnerable, length=-1, exit=3221225477\n\nsafe, length=-1, exit=2\nCopy rejected with code -2.\nsafe, length=17, exit=2\nCopy rejected with code -3.\nsafe, length=0, exit=0\nCopied 0 bytes.\nsafe, length=16, exit=0\nCopied 16 bytes.'}, {'name': 'Black-box bounded CLI tests', 'status': 'PASS', 'summary': 'All 9 black-box CLI inputs matched expected results within signed 32-bit bounds and buffer capacity 16.', 'command': "'C:\\msys64\\mingw64\\bin\\gcc.EXE' -std=c11 -Wall -Wextra -Wconversion -Wsign-conversion -I 'D:\\Study\\SoftSecProject\\CodeSoftSec\\csrc\\include' 'D:\\Study\\SoftSecProject\\CodeSoftSec\\csrc\\safe\\buffer_copy.c' 'D:\\Study\\SoftSecProject\\CodeSoftSec\\csrc\\cli\\buffer_copy_cli.c' -o 'C:\\Users\\ADMIN\\AppData\\Local\\Temp\\lms-c-analysis-le3tnmlp\\buffer_copy_blackbox.exe'", 'details': "input='-2147483648', expected_exit=2, actual_exit=2, error=none\nCopy rejected with code -2.\ninput='-1', expected_exit=2, actual_exit=2, error=none\nCopy rejected with code -2.\ninput='0', expected_exit=0, actual_exit=0, error=none\nCopied 0 bytes.\ninput='1', expected_exit=0, actual_exit=0, error=none\nCopied 1 bytes.\ninput='15', expected_exit=0, actual_exit=0, error=none\nCopied 15 bytes.\ninput='16', expected_exit=0, actual_exit=0, error=none\nCopied 16 bytes.\ninput='17', expected_exit=2, actual_exit=2, error=none\nCopy rejected with code -3.\ninput='2147483647', expected_exit=2, actual_exit=2, error=none\nCopy rejected with code -3.\ninput='not-an-integer', expected_exit=64, actual_exit=64, error=none\nInvalid integer length."}, {'name': 'Sanitizer fuzzing', 'status': 'UNAVAILABLE', 'summary': 'The installed compiler cannot link ASan/UBSan runtimes; the deterministic fuzzer will run without sanitizers.', 'command': "'C:\\msys64\\mingw64\\bin\\gcc.EXE' -std=c11 -Wall -Wextra -Wconversion -Wsign-conversion -I 'D:\\Study\\SoftSecProject\\CodeSoftSec\\csrc\\include' -fsanitize=address,undefined -fno-omit-frame-pointer 'D:\\Study\\SoftSecProject\\CodeSoftSec\\csrc\\safe\\buffer_copy.c' 'D:\\Study\\SoftSecProject\\CodeSoftSec\\csrc\\harness\\fuzz_buffer_copy.c' -o 'C:\\Users\\ADMIN\\AppData\\Local\\Temp\\lms-c-analysis-le3tnmlp\\fuzz_buffer_copy.exe'", 'details': 'C:/msys64/mingw64/bin/../lib/gcc/x86_64-w64-mingw32/16.2.0/../../../../x86_64-w64-mingw32/bin/ld.exe: cannot find -lasan: No such file or directory\nC:/msys64/mingw64/bin/../lib/gcc/x86_64-w64-mingw32/16.2.0/../../../../x86_64-w64-mingw32/bin/ld.exe: cannot find -lubsan: No such file or directory\ncollect2.exe: error: ld returned 1 exit status'}, {'name': 'Deterministic mutation fuzzing', 'status': 'PASS', 'summary': 'Completed 10000 deterministic mutation-fuzz iterations with seed 12648430 without sanitizers.', 'command': "'C:\\Users\\ADMIN\\AppData\\Local\\Temp\\lms-c-analysis-le3tnmlp\\fuzz_buffer_copy.exe' 10000 12648430", 'details': 'PASS: 10000 iterations completed with seed 12648430.\nCOVERAGE total=10000 negative=2025 zero=1019 valid_positive=3318 over_capacity=1638 integer_extreme=2000'}], 'report_path': 'D:\\Study\\SoftSecProject\\CodeSoftSec\\reports\\c_analysis\\latest_report.json', 'fuzzing': {'black_box': {'mode': 'Black-box CLI boundary testing', 'bounds': {'signed_int_min': -2147483648, 'signed_int_max': 2147483647, 'buffer_capacity': 16, 'timeout_seconds_per_case': 10}, 'seed_data': ['-2147483648', '-1', '0', '1', '15', '16', '17', '2147483647', 'not-an-integer'], 'coverage': {'cases_total': 9, 'cases_passed': 9, 'input_classes': ['INT_MIN', 'negative', 'zero', 'positive in-range', 'exact capacity', 'over capacity', 'INT_MAX', 'malformed integer']}, 'cases': [{'input': '-2147483648', 'expected_exit': 2, 'actual_exit': 2, 'passed': True, 'timed_out': False, 'execution_error': None}, {'input': '-1', 'expected_exit': 2, 'actual_exit': 2, 'passed': True, 'timed_out': False, 'execution_error': None}, {'input': '0', 'expected_exit': 0, 'actual_exit': 0, 'passed': True, 'timed_out': False, 'execution_error': None}, {'input': '1', 'expected_exit': 0, 'actual_exit': 0, 'passed': True, 'timed_out': False, 'execution_error': None}, {'input': '15', 'expected_exit': 0, 'actual_exit': 0, 'passed': True, 'timed_out': False, 'execution_error': None}, {'input': '16', 'expected_exit': 0, 'actual_exit': 0, 'passed': True, 'timed_out': False, 'execution_error': None}, {'input': '17', 'expected_exit': 2, 'actual_exit': 2, 'passed': True, 'timed_out': False, 'execution_error': None}, {'input': '2147483647', 'expected_exit': 2, 'actual_exit': 2, 'passed': True, 'timed_out': False, 'execution_error': None}, {'input': 'not-an-integer', 'expected_exit': 64, 'actual_exit': 64, 'passed': True, 'timed_out': False, 'execution_error': None}]}, 'white_box': {'mode': 'White-box deterministic direct-call fuzzing', 'seed': 12648430, 'iterations': 10000, 'bounds': {'buffer_capacity': 16, 'signed_int_min': -2147483648, 'signed_int_max': 2147483647, 'random_length_min': -48, 'random_length_max': 48, 'timeout_seconds': 30}, 'seed_data': [-2147483648, -1, 0, 1, 15, 16, 17, 2147483647], 'coverage': {'total': 10000, 'negative': 2025, 'zero': 1019, 'valid_positive': 3318, 'over_capacity': 1638, 'integer_extreme': 2000, 'input_classes_covered': 5, 'input_classes_total': 5}, 'sanitizers': 'not available', 'status': 'PASS'}}, 'scope': 'Bounded buffer-copy model, GCC analyzer, CBMC, Z3/SMT, ASan/UBSan, black-box boundary tests, and white-box fuzzing.', 'model_constraints': ['valid_length = (length >= 0 AND length <= source_size AND length <= destination_capacity)', 'NOT valid_length implies transition to S2_REJECT', 'valid_length implies transition to S3_COPY', 'copied implies (length >= 0 AND length <= source_size AND length <= destination_capacity)']}
```

### A.5 CBMC (Tầng 4)

#### A.5.1 Tổng hợp phiên bản và mã thoát

```text
CBMC_VERSION=5.95.1 (cbmc-5.95.1)
VULN_EXIT=10
SAFE_EXIT=0
```

#### A.5.2 Bản vulnerable - nhật ký đầy đủ

```text
CBMC version 5.95.1 (cbmc-5.95.1) 64-bit x86_64 linux
Parsing csrc/vulnerable/buffer_copy.c
Parsing csrc/harness/cbmc_buffer_copy_harness.c
Converting
Type-checking buffer_copy
Type-checking cbmc_buffer_copy_harness
Generating GOTO Program
Adding CPROVER library (x86_64)
Removal of function pointers and virtual functions
Generic Property Instrumentation
Running with 8 object bits, 56 offset bits (default)
Starting Bounded Model Checking
Runtime Symex: 0.00333941s
size of program expression: 197 steps
simple slicing removed 96 assignments
Generated 29 VCC(s), 2 remaining after simplification
Runtime Postprocess Equation: 1.3497e-05s
Passing problem to propositional reduction
converting SSA
Runtime Convert SSA: 0.000482375s
Running propositional reduction
Post-processing
Runtime Post-process: 1.0984e-05s
Solving with MiniSAT 2.2.1 with simplifier
871 variables, 397 clauses
SAT checker: instance is SATISFIABLE
Runtime Solver: 0.00166527s
Runtime decision procedure: 0.00484046s
Building error trace

** Results:
<builtin-library-memcpy> function memcpy
[memcpy.pointer.1] line 33 same object violation in (const char *)(const void *)source >= (const char *)(void *)destination + (signed long int)(size_t)length: SUCCESS
[memcpy.pointer_arithmetic.1] line 33 pointer relation: pointer NULL in (const char *)(const void *)source: SUCCESS
[memcpy.pointer_arithmetic.2] line 33 pointer relation: pointer invalid in (const char *)(const void *)source: SUCCESS
[memcpy.pointer_arithmetic.3] line 33 pointer relation: deallocated dynamic object in (const char *)(const void *)source: SUCCESS
[memcpy.pointer_arithmetic.4] line 33 pointer relation: dead object in (const char *)(const void *)source: SUCCESS
[memcpy.pointer_arithmetic.5] line 33 pointer relation: pointer outside object bounds in (const char *)(const void *)source: SUCCESS
[memcpy.pointer_arithmetic.6] line 33 pointer relation: invalid integer address in (const char *)(const void *)source: SUCCESS
[memcpy.pointer_arithmetic.7] line 33 pointer relation: pointer NULL in (const char *)(void *)destination + (signed long int)(size_t)length: SUCCESS
[memcpy.pointer_arithmetic.8] line 33 pointer relation: pointer invalid in (const char *)(void *)destination + (signed long int)(size_t)length: SUCCESS
[memcpy.pointer_arithmetic.9] line 33 pointer relation: deallocated dynamic object in (const char *)(void *)destination + (signed long int)(size_t)length: SUCCESS
[memcpy.pointer_arithmetic.10] line 33 pointer relation: dead object in (const char *)(void *)destination + (signed long int)(size_t)length: SUCCESS
[memcpy.pointer_arithmetic.11] line 33 pointer relation: pointer outside object bounds in (const char *)(void *)destination + (signed long int)(size_t)length: SUCCESS
[memcpy.pointer_arithmetic.12] line 33 pointer relation: invalid integer address in (const char *)(void *)destination + (signed long int)(size_t)length: SUCCESS
[memcpy.pointer.2] line 34 same object violation in (const char *)(void *)destination >= (const char *)(const void *)source + (signed long int)(size_t)length: SUCCESS
[memcpy.pointer_arithmetic.13] line 34 pointer relation: pointer NULL in (const char *)(void *)destination: SUCCESS
[memcpy.pointer_arithmetic.14] line 34 pointer relation: pointer invalid in (const char *)(void *)destination: SUCCESS
[memcpy.pointer_arithmetic.15] line 34 pointer relation: deallocated dynamic object in (const char *)(void *)destination: SUCCESS
[memcpy.pointer_arithmetic.16] line 34 pointer relation: dead object in (const char *)(void *)destination: SUCCESS
[memcpy.pointer_arithmetic.17] line 34 pointer relation: pointer outside object bounds in (const char *)(void *)destination: SUCCESS
[memcpy.pointer_arithmetic.18] line 34 pointer relation: invalid integer address in (const char *)(void *)destination: SUCCESS
[memcpy.pointer_arithmetic.19] line 34 pointer relation: pointer NULL in (const char *)(const void *)source + (signed long int)(size_t)length: SUCCESS
[memcpy.pointer_arithmetic.20] line 34 pointer relation: pointer invalid in (const char *)(const void *)source + (signed long int)(size_t)length: SUCCESS
[memcpy.pointer_arithmetic.21] line 34 pointer relation: deallocated dynamic object in (const char *)(const void *)source + (signed long int)(size_t)length: SUCCESS
[memcpy.pointer_arithmetic.22] line 34 pointer relation: dead object in (const char *)(const void *)source + (signed long int)(size_t)length: SUCCESS
[memcpy.pointer_arithmetic.23] line 34 pointer relation: pointer outside object bounds in (const char *)(const void *)source + (signed long int)(size_t)length: SUCCESS
[memcpy.pointer_arithmetic.24] line 34 pointer relation: invalid integer address in (const char *)(const void *)source + (signed long int)(size_t)length: SUCCESS

csrc/vulnerable/buffer_copy.c function copy_buffer
[copy_buffer.precondition_instance.1] line 27 memcpy src/dst overlap: SUCCESS
[copy_buffer.precondition_instance.2] line 27 memcpy source region readable: FAILURE
[copy_buffer.precondition_instance.3] line 27 memcpy destination region writeable: FAILURE

Trace for copy_buffer.precondition_instance.2:

State 12 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source={ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } ({ 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000 })

State 13 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source[0l]=0 (00000000)

State 14 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source[1l]=0 (00000000)

State 15 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source[2l]=0 (00000000)

State 16 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source[3l]=0 (00000000)

State 17 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source[4l]=0 (00000000)

State 18 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source[5l]=0 (00000000)

State 19 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source[6l]=0 (00000000)

State 20 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source[7l]=0 (00000000)

State 21 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source[8l]=0 (00000000)

State 22 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source[9l]=0 (00000000)

State 23 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source[10l]=0 (00000000)

State 24 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source[11l]=0 (00000000)

State 25 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source[12l]=0 (00000000)

State 26 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source[13l]=0 (00000000)

State 27 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source[14l]=0 (00000000)

State 28 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source[15l]=0 (00000000)

State 30 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination={ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } ({ 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000 })

State 31 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination[0l]=0 (00000000)

State 32 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination[1l]=0 (00000000)

State 33 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination[2l]=0 (00000000)

State 34 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination[3l]=0 (00000000)

State 35 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination[4l]=0 (00000000)

State 36 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination[5l]=0 (00000000)

State 37 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination[6l]=0 (00000000)

State 38 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination[7l]=0 (00000000)

State 39 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination[8l]=0 (00000000)

State 40 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination[9l]=0 (00000000)

State 41 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination[10l]=0 (00000000)

State 42 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination[11l]=0 (00000000)

State 43 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination[12l]=0 (00000000)

State 44 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination[13l]=0 (00000000)

State 45 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination[14l]=0 (00000000)

State 46 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination[15l]=0 (00000000)

State 49 file csrc/harness/cbmc_buffer_copy_harness.c function main line 9 thread 0
----------------------------------------------------
  return_value_nondet_int=-2147483648 (10000000 00000000 00000000 00000000)

State 50 file csrc/harness/cbmc_buffer_copy_harness.c function main line 9 thread 0
----------------------------------------------------
  length=-2147483648 (10000000 00000000 00000000 00000000)

State 53 file csrc/harness/cbmc_buffer_copy_harness.c function main line 11 thread 0
----------------------------------------------------
  source=source!0@1 (00000010 00000000 00000000 00000000 00000000 00000000 00000000 00000000)

State 54 file csrc/harness/cbmc_buffer_copy_harness.c function main line 11 thread 0
----------------------------------------------------
  source_size=sizeof(unsigned char [16l]) /*16ul*/  (00000000 00000000 00000000 00000000 00000000 00000000 00000000 00010000)

State 55 file csrc/harness/cbmc_buffer_copy_harness.c function main line 11 thread 0
----------------------------------------------------
  destination=destination!0@1 (00000011 00000000 00000000 00000000 00000000 00000000 00000000 00000000)

State 56 file csrc/harness/cbmc_buffer_copy_harness.c function main line 11 thread 0
----------------------------------------------------
  destination_capacity=sizeof(unsigned char [16l]) /*16ul*/  (00000000 00000000 00000000 00000000 00000000 00000000 00000000 00010000)

State 57 file csrc/harness/cbmc_buffer_copy_harness.c function main line 11 thread 0
----------------------------------------------------
  length=-2147483648 (10000000 00000000 00000000 00000000)

Violated property:
  file csrc/vulnerable/buffer_copy.c function copy_buffer line 27 thread 0
  memcpy source region readable
  R_OK((const void *)source, (size_t)length)



Trace for copy_buffer.precondition_instance.3:

State 12 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source={ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } ({ 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000 })

State 13 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source[0l]=0 (00000000)

State 14 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source[1l]=0 (00000000)

State 15 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source[2l]=0 (00000000)

State 16 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source[3l]=0 (00000000)

State 17 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source[4l]=0 (00000000)

State 18 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source[5l]=0 (00000000)

State 19 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source[6l]=0 (00000000)

State 20 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source[7l]=0 (00000000)

State 21 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source[8l]=0 (00000000)

State 22 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source[9l]=0 (00000000)

State 23 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source[10l]=0 (00000000)

State 24 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source[11l]=0 (00000000)

State 25 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source[12l]=0 (00000000)

State 26 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source[13l]=0 (00000000)

State 27 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source[14l]=0 (00000000)

State 28 file csrc/harness/cbmc_buffer_copy_harness.c function main line 7 thread 0
----------------------------------------------------
  source[15l]=0 (00000000)

State 30 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination={ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } ({ 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000 })

State 31 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination[0l]=0 (00000000)

State 32 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination[1l]=0 (00000000)

State 33 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination[2l]=0 (00000000)

State 34 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination[3l]=0 (00000000)

State 35 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination[4l]=0 (00000000)

State 36 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination[5l]=0 (00000000)

State 37 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination[6l]=0 (00000000)

State 38 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination[7l]=0 (00000000)

State 39 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination[8l]=0 (00000000)

State 40 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination[9l]=0 (00000000)

State 41 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination[10l]=0 (00000000)

State 42 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination[11l]=0 (00000000)

State 43 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination[12l]=0 (00000000)

State 44 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination[13l]=0 (00000000)

State 45 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination[14l]=0 (00000000)

State 46 file csrc/harness/cbmc_buffer_copy_harness.c function main line 8 thread 0
----------------------------------------------------
  destination[15l]=0 (00000000)

State 49 file csrc/harness/cbmc_buffer_copy_harness.c function main line 9 thread 0
----------------------------------------------------
  return_value_nondet_int=-2147483648 (10000000 00000000 00000000 00000000)

State 50 file csrc/harness/cbmc_buffer_copy_harness.c function main line 9 thread 0
----------------------------------------------------
  length=-2147483648 (10000000 00000000 00000000 00000000)

State 53 file csrc/harness/cbmc_buffer_copy_harness.c function main line 11 thread 0
----------------------------------------------------
  source=source!0@1 (00000010 00000000 00000000 00000000 00000000 00000000 00000000 00000000)

State 54 file csrc/harness/cbmc_buffer_copy_harness.c function main line 11 thread 0
----------------------------------------------------
  source_size=sizeof(unsigned char [16l]) /*16ul*/  (00000000 00000000 00000000 00000000 00000000 00000000 00000000 00010000)

State 55 file csrc/harness/cbmc_buffer_copy_harness.c function main line 11 thread 0
----------------------------------------------------
  destination=destination!0@1 (00000011 00000000 00000000 00000000 00000000 00000000 00000000 00000000)

State 56 file csrc/harness/cbmc_buffer_copy_harness.c function main line 11 thread 0
----------------------------------------------------
  destination_capacity=sizeof(unsigned char [16l]) /*16ul*/  (00000000 00000000 00000000 00000000 00000000 00000000 00000000 00010000)

State 57 file csrc/harness/cbmc_buffer_copy_harness.c function main line 11 thread 0
----------------------------------------------------
  length=-2147483648 (10000000 00000000 00000000 00000000)

Violated property:
  file csrc/vulnerable/buffer_copy.c function copy_buffer line 27 thread 0
  memcpy source region readable
  R_OK((const void *)source, (size_t)length)


Violated property:
  file csrc/vulnerable/buffer_copy.c function copy_buffer line 27 thread 0
  memcpy destination region writeable
  W_OK((void *)destination, (size_t)length)



** 2 of 29 failed (2 iterations)
VERIFICATION FAILED
```

#### A.5.3 Bản safe - nhật ký đầy đủ

```text
CBMC version 5.95.1 (cbmc-5.95.1) 64-bit x86_64 linux
Parsing csrc/safe/buffer_copy.c
Parsing csrc/harness/cbmc_buffer_copy_harness.c
Converting
Type-checking buffer_copy
Type-checking cbmc_buffer_copy_harness
Generating GOTO Program
Adding CPROVER library (x86_64)
Removal of function pointers and virtual functions
Generic Property Instrumentation
Running with 8 object bits, 56 offset bits (default)
Starting Bounded Model Checking
Runtime Symex: 0.00511326s
size of program expression: 219 steps
simple slicing removed 113 assignments
Generated 29 VCC(s), 2 remaining after simplification
Runtime Postprocess Equation: 4.627e-05s
Passing problem to propositional reduction
converting SSA
Runtime Convert SSA: 0.00105054s
Running propositional reduction
Post-processing
Runtime Post-process: 5.163e-06s
Solving with MiniSAT 2.2.1 with simplifier
1003 variables, 535 clauses
SAT checker: instance is UNSATISFIABLE
Runtime Solver: 0.00151237s
Runtime decision procedure: 0.00534244s

** Results:
<builtin-library-memcpy> function memcpy
[memcpy.pointer.1] line 33 same object violation in (const char *)(const void *)source >= (const char *)(void *)destination + (signed long int)copy_length: SUCCESS
[memcpy.pointer_arithmetic.1] line 33 pointer relation: pointer NULL in (const char *)(const void *)source: SUCCESS
[memcpy.pointer_arithmetic.2] line 33 pointer relation: pointer invalid in (const char *)(const void *)source: SUCCESS
[memcpy.pointer_arithmetic.3] line 33 pointer relation: deallocated dynamic object in (const char *)(const void *)source: SUCCESS
[memcpy.pointer_arithmetic.4] line 33 pointer relation: dead object in (const char *)(const void *)source: SUCCESS
[memcpy.pointer_arithmetic.5] line 33 pointer relation: pointer outside object bounds in (const char *)(const void *)source: SUCCESS
[memcpy.pointer_arithmetic.6] line 33 pointer relation: invalid integer address in (const char *)(const void *)source: SUCCESS
[memcpy.pointer_arithmetic.7] line 33 pointer relation: pointer NULL in (const char *)(void *)destination + (signed long int)copy_length: SUCCESS
[memcpy.pointer_arithmetic.8] line 33 pointer relation: pointer invalid in (const char *)(void *)destination + (signed long int)copy_length: SUCCESS
[memcpy.pointer_arithmetic.9] line 33 pointer relation: deallocated dynamic object in (const char *)(void *)destination + (signed long int)copy_length: SUCCESS
[memcpy.pointer_arithmetic.10] line 33 pointer relation: dead object in (const char *)(void *)destination + (signed long int)copy_length: SUCCESS
[memcpy.pointer_arithmetic.11] line 33 pointer relation: pointer outside object bounds in (const char *)(void *)destination + (signed long int)copy_length: SUCCESS
[memcpy.pointer_arithmetic.12] line 33 pointer relation: invalid integer address in (const char *)(void *)destination + (signed long int)copy_length: SUCCESS
[memcpy.pointer.2] line 34 same object violation in (const char *)(void *)destination >= (const char *)(const void *)source + (signed long int)copy_length: SUCCESS
[memcpy.pointer_arithmetic.13] line 34 pointer relation: pointer NULL in (const char *)(void *)destination: SUCCESS
[memcpy.pointer_arithmetic.14] line 34 pointer relation: pointer invalid in (const char *)(void *)destination: SUCCESS
[memcpy.pointer_arithmetic.15] line 34 pointer relation: deallocated dynamic object in (const char *)(void *)destination: SUCCESS
[memcpy.pointer_arithmetic.16] line 34 pointer relation: dead object in (const char *)(void *)destination: SUCCESS
[memcpy.pointer_arithmetic.17] line 34 pointer relation: pointer outside object bounds in (const char *)(void *)destination: SUCCESS
[memcpy.pointer_arithmetic.18] line 34 pointer relation: invalid integer address in (const char *)(void *)destination: SUCCESS
[memcpy.pointer_arithmetic.19] line 34 pointer relation: pointer NULL in (const char *)(const void *)source + (signed long int)copy_length: SUCCESS
[memcpy.pointer_arithmetic.20] line 34 pointer relation: pointer invalid in (const char *)(const void *)source + (signed long int)copy_length: SUCCESS
[memcpy.pointer_arithmetic.21] line 34 pointer relation: deallocated dynamic object in (const char *)(const void *)source + (signed long int)copy_length: SUCCESS
[memcpy.pointer_arithmetic.22] line 34 pointer relation: dead object in (const char *)(const void *)source + (signed long int)copy_length: SUCCESS
[memcpy.pointer_arithmetic.23] line 34 pointer relation: pointer outside object bounds in (const char *)(const void *)source + (signed long int)copy_length: SUCCESS
[memcpy.pointer_arithmetic.24] line 34 pointer relation: invalid integer address in (const char *)(const void *)source + (signed long int)copy_length: SUCCESS

csrc/safe/buffer_copy.c function copy_buffer
[copy_buffer.precondition_instance.1] line 28 memcpy src/dst overlap: SUCCESS
[copy_buffer.precondition_instance.2] line 28 memcpy source region readable: SUCCESS
[copy_buffer.precondition_instance.3] line 28 memcpy destination region writeable: SUCCESS

** 0 of 29 failed (1 iterations)
VERIFICATION SUCCESSFUL
```

### A.6 ASan/UBSan (Tầng 5, Docker `gcc:13`)

```text
=== BUILD VULNERABLE (ASan+UBSan) ===
BUILD_OK
=== BUILD SAFE (ASan+UBSan) ===
BUILD_OK

=== RUN vulnerable length=-1 ===
=================================================================
==22==ERROR: AddressSanitizer: negative-size-param: (size=-1)
    #0 0x7c172baabdd8 in __interceptor_memcpy (/usr/local/lib64/libasan.so.8+0x70dd8)
    #1 0x4012d5 in copy_buffer (/tmp/vuln+0x4012d5)
    #2 0x40179c in main (/tmp/vuln+0x40179c)
    #3 0x7c172b274249  (/lib/x86_64-linux-gnu/libc.so.6+0x27249) (BuildId: 93ac61ec5a8eb1396f9fbd350e3169a558528a40)
    #4 0x7c172b274304 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x27304) (BuildId: 93ac61ec5a8eb1396f9fbd350e3169a558528a40)
    #5 0x401190 in _start (/tmp/vuln+0x401190)

Address 0x7c1729000040 is located in stack of thread T0 at offset 64 in frame
    #0 0x401324 in main (/tmp/vuln+0x401324)

  This frame has 3 object(s):
    [32, 40) 'end' (line 12)
    [64, 80) 'source' (line 10) <== Memory access at offset 64 is inside this variable
    [96, 112) 'destination' (line 11)
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: negative-size-param (/usr/local/lib64/libasan.so.8+0x70dd8) in __interceptor_memcpy
==22==ABORTING
VULN_EXIT=1

=== RUN safe length=-1 ===
Copy rejected with code -2.
SAFE_M1_EXIT=2

=== RUN safe length=17 ===
Copy rejected with code -3.
SAFE_17_EXIT=2
```

### A.7 Fuzzing pipeline (Tầng 6)

Lệnh: `uv run python main.py --fuzz --iterations 100 --seed 12648430`

```text
[PASS       ] Black-box CLI boundary fuzzing: 9/9 black-box CLI inputs matched the expected exit codes, covering 8 input classes.
[PASS       ] White-box deterministic fuzzing: Completed 100 deterministic direct-call iterations with seed 12648430, covering 5/5 input classes without a crash, sanitizer report, or hang.
[PASS       ] Python fuzzing (authentication): 100 iterations with seed 12648430; 0 findings.
[PASS       ] Python fuzzing (email): 100 iterations with seed 12648430; 0 findings.
[PASS       ] Python fuzzing (email_retry): 100 iterations with seed 12648430; 0 findings.
Seed 12648430, 100 iterations per target, 5 stages, PASS
Artifacts: D:\Study\SoftSecProject\CodeSoftSec\reports\fuzzing
```
