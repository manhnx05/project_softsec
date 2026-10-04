import json
import shutil

import pytest

from src.c_analysis.model import (
    BUFFER_CAPACITY,
    MODEL_STATES,
    evaluate_copy,
    find_bounded_counterexample,
    validate_model,
)
from src.c_analysis.runner import run_c_analysis


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
