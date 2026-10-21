import ctypes
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from src.c_analysis.model import (
    BUFFER_CAPACITY,
    MODEL_STATES,
    evaluate_copy,
    find_bounded_counterexample,
    validate_model,
)
from src.c_analysis.runner import run_c_analysis
from src.specification.loader import load_test_scenarios

PROJECT_ROOT = Path(__file__).resolve().parents[1]
C_ROOT = PROJECT_ROOT / "csrc"



def test_buffer_copy_model_has_valid_state_graph():

    assert validate_model() == []
    assert MODEL_STATES == (
        "S0_INPUT",
        "S1_VALIDATE",
        "S2_REJECT",
        "S3_COPY",
        "S4_DONE",
    )


def test_vulnerable_model_exposes_negative_length_counterexample():

    evaluation = evaluate_copy(
        "vulnerable",
        length=-1,
        source_size=BUFFER_CAPACITY,
        destination_capacity=BUFFER_CAPACITY,
    )

    assert evaluation.copied is True
    assert evaluation.trace == (
        "S0_INPUT",
        "S1_VALIDATE",
        "S3_COPY",
        "S4_DONE",
    )
    assert "negative length is converted to an unsigned size" in (
        evaluation.violations
    )


def test_safe_model_rejects_invalid_ranges_and_accepts_boundaries():

    assert evaluate_copy("safe", -1, 16, 16).copied is False
    assert evaluate_copy("safe", 17, 16, 16).copied is False
    assert evaluate_copy("safe", 0, 16, 16).copied is True
    assert evaluate_copy("safe", 16, 16, 16).copied is True
    assert evaluate_copy("safe", 2, 1, 16).copied is False


def test_bounded_model_finds_vulnerable_case_and_no_safe_case():

    lengths = range(-32, 33)

    assert find_bounded_counterexample("vulnerable", lengths) is not None
    assert find_bounded_counterexample("safe", lengths) is None


def test_model_rejects_unknown_implementation_and_negative_sizes():

    with pytest.raises(ValueError, match="Unknown implementation"):
        evaluate_copy("unknown", 1, 1, 1)

    with pytest.raises(ValueError, match="cannot be negative"):
        evaluate_copy("safe", 1, -1, 1)


def test_end_to_end_c_analysis_writes_explicit_report(tmp_path):

    if shutil.which("gcc") is None:
        pytest.skip("GCC is required for the end-to-end C analysis test.")

    report_path = tmp_path / "c_analysis.json"
    report = run_c_analysis(
        iterations=64,
        seed=12345,
        report_path=report_path,
    )
    saved_report = json.loads(report_path.read_text(encoding="utf-8"))
    statuses = {check.name: check.status for check in report.checks}

    assert report_path.exists()
    assert saved_report["checks"]
    assert statuses["Vulnerable model counterexample"] == "FINDING"
    assert statuses["Safe model bounded check"] == "PASS"
    assert statuses["Z3 vulnerable guard counterexample"] == "FINDING"
    assert statuses["Z3 safe guard verification"] == "PASS"
    z3_counterexample = next(
        check
        for check in report.checks
        if check.name == "Z3 vulnerable guard counterexample"
    )
    assert "length=-1" in z3_counterexample.details
    assert "source_size=16" in z3_counterexample.details
    assert "destination_capacity=16" in z3_counterexample.details
    assert "CBMC bounded model checking" in statuses
    assert "Sanitizer fuzzing" in statuses

    if statuses["Sanitizer fuzzing"] == "UNAVAILABLE":
        assert statuses["Native dynamic boundary tests"] == "FINDING"
        assert statuses["Deterministic mutation fuzzing"] == "PASS"
    else:
        assert statuses["Sanitizer runtime (vulnerable)"] == "FINDING"
        assert statuses["Sanitizer fuzzing"] == "PASS"


# =============================================================
# SCENARIO MATRIX: C MEMORY SAFETY TESTS
# =============================================================

def _build_c_shared_lib(implementation: str, tmp_path: Path):
    """Biên dịch buffer_copy C thành shared library (.dll/.so) để test bằng ctypes."""
    compiler = shutil.which("gcc")
    if compiler is None:
        return None

    source_path = C_ROOT / implementation / "buffer_copy.c"
    lib_ext = ".dll" if subprocess.os.name == "nt" else ".so"
    output_lib = tmp_path / f"lib_buffer_copy_{implementation}{lib_ext}"

    cmd = [
        compiler,
        "-shared",
        "-fPIC",
        "-I",
        str(C_ROOT / "include"),
        str(source_path),
        "-o",
        str(output_lib),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if res.returncode != 0:
        return None

    c_lib = ctypes.CDLL(str(output_lib))
    c_lib.copy_buffer.argtypes = [
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.c_size_t,
        ctypes.c_int,
    ]
    c_lib.copy_buffer.restype = ctypes.c_int
    return c_lib


def test_scenario_matrix_contains_all_required_memory_scenarios():
    """Kiểm tra ma trận test_scenarios.yaml chứa đầy đủ kịch bản cấp Memory."""
    scenarios = load_test_scenarios()
    mem_ids = {s.id for s in scenarios if s.level == "Memory"}
    assert "TS-MEM-BOF-001" in mem_ids
    assert "TS-MEM-OBO-001" in mem_ids
    assert "TS-MEM-OOB-001" in mem_ids
    assert "TS-MEM-NULL-001" in mem_ids


def test_scenario_mem_bof_buffer_overflow_and_signed_conversion(tmp_path):
    """
    Kịch bản TS-MEM-BOF-001:
    Tràn bộ đệm (Buffer Overflow): Nhập chuỗi độ dài > BUFFER_SIZE hoặc negative length.
    CWE-120 / CWE-195.
    """
    scenarios = load_test_scenarios()
    scenario = next(s for s in scenarios if s.id == "TS-MEM-BOF-001")
    assert scenario.level == "Memory"
    assert "CWE-120" in scenario.hazard_type

    # 1. Kiểm tra trên mô hình hình thức (Bounded Model)
    # Bản vulnerable cho phép negative length vượt qua guard
    vulnerable_eval = evaluate_copy("vulnerable", length=-1, source_size=16, destination_capacity=16)
    assert vulnerable_eval.copied is True
    assert "negative length is converted to an unsigned size" in vulnerable_eval.violations

    # Bản safe chặn cả negative length và độ dài > capacity
    safe_negative = evaluate_copy("safe", length=-1, source_size=16, destination_capacity=16)
    assert safe_negative.copied is False

    safe_overlong = evaluate_copy("safe", length=32, source_size=16, destination_capacity=16)
    assert safe_overlong.copied is False

    # 2. Kiểm tra C Runtime trực tiếp qua ctypes
    safe_lib = _build_c_shared_lib("safe", tmp_path)
    if safe_lib:
        src = (ctypes.c_ubyte * 32)(*([0x41] * 32))
        dst = (ctypes.c_ubyte * 16)()

        # Negative length -> BUFFER_COPY_NEGATIVE_LENGTH (-2)
        code_neg = safe_lib.copy_buffer(src, 16, dst, 16, -1)
        assert code_neg == -2

        # Length > capacity (32 > 16) -> BUFFER_COPY_OUT_OF_RANGE (-3)
        code_overflow = safe_lib.copy_buffer(src, 32, dst, 16, 32)
        assert code_overflow == -3


def test_scenario_mem_obo_off_by_one_boundary_error(tmp_path):
    """
    Kịch bản TS-MEM-OBO-001:
    Off-by-one Error: Ghi đúng BUFFER_SIZE + 1 ký tự (17 bytes trên buffer 16 bytes).
    CWE-193.
    """
    scenarios = load_test_scenarios()
    scenario = next(s for s in scenarios if s.id == "TS-MEM-OBO-001")
    assert scenario.level == "Memory"
    assert "CWE-193" in scenario.hazard_type

    capacity = 16
    exact_overflow_len = capacity + 1  # 17

    # 1. Kiểm tra mô hình
    safe_obo = evaluate_copy("safe", length=exact_overflow_len, source_size=exact_overflow_len, destination_capacity=capacity)
    assert safe_obo.copied is False

    # Biên hợp lệ (16 bytes) phải được chấp nhận
    safe_valid_boundary = evaluate_copy("safe", length=capacity, source_size=capacity, destination_capacity=capacity)
    assert safe_valid_boundary.copied is True
    assert safe_valid_boundary.violations == ()

    # 2. Kiểm tra C Runtime trực tiếp
    safe_lib = _build_c_shared_lib("safe", tmp_path)
    if safe_lib:
        src = (ctypes.c_ubyte * 17)(*([0x42] * 17))
        dst = (ctypes.c_ubyte * 16)()

        # Ghi đúng 16 byte -> thành công (BUFFER_COPY_OK = 0)
        code_ok = safe_lib.copy_buffer(src, 17, dst, 16, 16)
        assert code_ok == 0

        # Ghi 17 byte (BUFFER_SIZE + 1) -> BUFFER_COPY_OUT_OF_RANGE (-3)
        code_obo = safe_lib.copy_buffer(src, 17, dst, 16, 17)
        assert code_obo == -3


def test_scenario_mem_oob_out_of_bounds_read_and_write(tmp_path):
    """
    Kịch bản TS-MEM-OOB-001:
    Out-of-bounds Read/Write: Đọc chỉ số ngoài mảng source (length > source_size).
    CWE-125 / CWE-787.
    """
    scenarios = load_test_scenarios()
    scenario = next(s for s in scenarios if s.id == "TS-MEM-OOB-001")
    assert scenario.level == "Memory"
    assert "CWE-125" in scenario.hazard_type

    source_size = 8
    dest_capacity = 16
    read_len = 12  # 12 <= 16 (dest), nhưng 12 > 8 (src) -> OOB Read

    # 1. Kiểm tra mô hình
    vulnerable_eval = evaluate_copy("vulnerable", length=read_len, source_size=source_size, destination_capacity=dest_capacity)
    assert vulnerable_eval.copied is True
    assert "copy length exceeds source buffer size" in vulnerable_eval.violations

    safe_eval = evaluate_copy("safe", length=read_len, source_size=source_size, destination_capacity=dest_capacity)
    assert safe_eval.copied is False

    # 2. Kiểm tra C Runtime
    vulnerable_lib = _build_c_shared_lib("vulnerable", tmp_path)
    safe_lib = _build_c_shared_lib("safe", tmp_path)

    if vulnerable_lib and safe_lib:
        src = (ctypes.c_ubyte * 8)(*([0x43] * 8))
        dst = (ctypes.c_ubyte * 16)()

        # Bản vulnerable bỏ qua source_size, cho phép đọc quá mảng -> trả về 0 (lỗ hổng)
        vuln_res = vulnerable_lib.copy_buffer(src, source_size, dst, dest_capacity, read_len)
        assert vuln_res == 0

        # Bản safe kiểm tra chặt chẽ -> từ chối với BUFFER_COPY_OUT_OF_RANGE (-3)
        safe_res = safe_lib.copy_buffer(src, source_size, dst, dest_capacity, read_len)
        assert safe_res == -3


def test_scenario_mem_null_pointer_dereference_protection(tmp_path):
    """
    Kịch bản TS-MEM-NULL-001:
    Null Pointer Dereference: Truyền con trỏ NULL vào hàm copy.
    CWE-476. Cả 2 hàm đều phải kiểm tra và trả về BUFFER_COPY_INVALID_ARGUMENT (-1).
    """
    scenarios = load_test_scenarios()
    scenario = next(s for s in scenarios if s.id == "TS-MEM-NULL-001")
    assert scenario.level == "Memory"
    assert "CWE-476" in scenario.hazard_type

    safe_lib = _build_c_shared_lib("safe", tmp_path)
    vuln_lib = _build_c_shared_lib("vulnerable", tmp_path)

    if safe_lib and vuln_lib:
        valid_buf = (ctypes.c_ubyte * 16)()
        null_ptr = ctypes.POINTER(ctypes.c_ubyte)()

        for lib in (safe_lib, vuln_lib):
            # Case 1: source == NULL
            res_null_src = lib.copy_buffer(null_ptr, 16, valid_buf, 16, 8)
            assert res_null_src == -1

            # Case 2: destination == NULL
            res_null_dst = lib.copy_buffer(valid_buf, 16, null_ptr, 16, 8)
            assert res_null_dst == -1

            # Case 3: Both == NULL
            res_both_null = lib.copy_buffer(null_ptr, 16, null_ptr, 16, 8)
            assert res_both_null == -1

