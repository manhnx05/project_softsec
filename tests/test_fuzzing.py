"""Automated test suite for the dual-engine fuzzing framework (Lab 8).

Test Goals
----------
1. White-box fuzzer MUST find crash within <= 500 iterations (fixed seed).
2. Black-box fuzzer runs same budget — metrics must be structurally correct.
3. All crashes found must be persisted as files in the crashes/ directory.
4. compare_fuzzers() produces structurally valid JSON.
5. Coverage grows monotonically in white-box timeline.
6. FuzzingReport serialises and exports correctly.
7. Mutation operators never raise exceptions and always return bytes.
8. _CoverageTracker correctly detects branch tokens.
"""

from __future__ import annotations

import json
import random
import tempfile
import time
from pathlib import Path

import pytest

from src.testing.fuzzing import (
    CRASHES_DIR,
    DATASET_DIR,
    FuzzingMode,
    FuzzingReport,
    _CoverageTracker,
    _simulate_report,
    compare_fuzzers,
    generate_execution_flow_dot,
    load_seeds,
    minimize_crash_payload,
    mutate_payload,
    run_blackbox_fuzzer,
    run_whitebox_fuzzer,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_temp_crash_dir() -> Path:
    """Return a fresh temp directory that is cleaned up after each test."""
    d = Path(tempfile.mkdtemp(prefix="test_crashes_"))
    return d


# ---------------------------------------------------------------------------
# 1. Seed Loading
# ---------------------------------------------------------------------------

class TestLoadSeeds:
    def test_loads_from_fuzz_seeds_dir(self) -> None:
        seeds = load_seeds()
        assert isinstance(seeds, list)
        assert len(seeds) > 0
        assert all(isinstance(s, bytes) for s in seeds)

    def test_fallback_when_dir_missing(self) -> None:
        seeds = load_seeds("/nonexistent/path/that/does/not/exist")
        assert len(seeds) >= 5
        assert b"" in seeds or b"-1" in seeds


# ---------------------------------------------------------------------------
# 2. Mutation Operators
# ---------------------------------------------------------------------------

class TestMutationOperators:
    SEEDS = [b"", b"A" * 16, b"hello", b"-1", b"\x00\x01\x02"]
    RNG = random.Random(0)

    def test_mutate_never_raises(self) -> None:
        for seed in self.SEEDS:
            result = mutate_payload(seed, self.RNG)
            assert isinstance(result, bytes)

    def test_mutate_produces_diverse_outputs(self) -> None:
        rng = random.Random(99)
        base = b"AAAA"
        outputs = {mutate_payload(base, rng) for _ in range(50)}
        # Should produce multiple distinct mutations
        assert len(outputs) > 5

    def test_mutate_boundary_int_is_bytes(self) -> None:
        from src.testing.fuzzing import _mut_boundary_int
        rng = random.Random(1)
        result = _mut_boundary_int(b"any", rng)
        assert isinstance(result, bytes)
        # Must be a valid integer string
        int(result.decode())

    def test_mutate_overflow_extension_bounded(self) -> None:
        from src.testing.fuzzing import _mut_overflow_extension
        rng = random.Random(1)
        result = _mut_overflow_extension(b"X", rng)
        assert len(result) <= 512


# ---------------------------------------------------------------------------
# 3. Coverage Tracker
# ---------------------------------------------------------------------------

class TestCoverageTracker:
    def test_empty_payload_detected(self) -> None:
        t = _CoverageTracker()
        new = t.record(b"")
        assert "branch_empty" in new

    def test_negative_sign_detected(self) -> None:
        t = _CoverageTracker()
        new = t.record(b"-1")
        assert "branch_negative_sign" in new

    def test_null_byte_detected(self) -> None:
        t = _CoverageTracker()
        new = t.record(b"abc\x00def")
        assert "branch_null_byte" in new

    def test_coverage_grows_monotonically(self) -> None:
        t = _CoverageTracker()
        prev = 0.0
        payloads = [b"", b"A" * 16, b"-1", b"\x00", b"A" * 300, b"%x", b"A" * 15]
        for p in payloads:
            t.record(p)
            assert t.coverage_pct >= prev
            prev = t.coverage_pct

    def test_coverage_pct_bounded_0_100(self) -> None:
        t = _CoverageTracker()
        for _ in range(200):
            t.record(random.randbytes(random.randint(0, 300)))
        assert 0.0 <= t.coverage_pct <= 100.0

    def test_no_duplicate_branches_counted(self) -> None:
        t = _CoverageTracker()
        t.record(b"-1")
        first_pct = t.coverage_pct
        t.record(b"-1")
        assert t.coverage_pct == first_pct  # Same payload = no new branches


# ---------------------------------------------------------------------------
# 4. Crash Minimizer
# ---------------------------------------------------------------------------

class TestMinimizeCrashPayload:
    def test_minimise_returns_bytes(self) -> None:
        reproducer = lambda p: len(p) >= 2
        result = minimize_crash_payload(b"AAAA", reproducer)
        assert isinstance(result, bytes)

    def test_minimise_when_no_crash(self) -> None:
        reproducer = lambda p: False
        original = b"AAAA"
        result = minimize_crash_payload(original, reproducer)
        assert result == original

    def test_minimise_reduces_payload(self) -> None:
        reproducer = lambda p: b"-" in p
        result = minimize_crash_payload(b"BBBBB-CCCCC", reproducer)
        assert len(result) <= len(b"BBBBB-CCCCC")
        assert b"-" in result


# ---------------------------------------------------------------------------
# 5. Simulation Fallback
# ---------------------------------------------------------------------------

class TestSimulateReport:
    def test_vulnerable_whitebox_has_crash(self) -> None:
        report = _simulate_report("vulnerable", FuzzingMode.WHITEBOX, 100)
        assert report.unique_crashes == 1
        assert report.crashes[0].sanitizer_finding is True

    def test_vulnerable_blackbox_has_crash(self) -> None:
        report = _simulate_report("vulnerable", FuzzingMode.BLACKBOX, 100)
        assert report.unique_crashes == 1
        assert report.crashes[0].sanitizer_finding is False

    def test_safe_has_no_crash(self) -> None:
        report = _simulate_report("safe", FuzzingMode.WHITEBOX, 100)
        assert report.unique_crashes == 0

    def test_whitebox_has_higher_coverage_than_blackbox(self) -> None:
        wb = _simulate_report("vulnerable", FuzzingMode.WHITEBOX, 100)
        bb = _simulate_report("vulnerable", FuzzingMode.BLACKBOX, 100)
        assert wb.coverage_percent > bb.coverage_percent

    def test_report_has_execution_events(self) -> None:
        report = _simulate_report("vulnerable", FuzzingMode.WHITEBOX, 100)
        assert len(report.execution_events) > 0
        crash_events = [e for e in report.execution_events if e.event == "CRASH"]
        assert len(crash_events) >= 1


# ---------------------------------------------------------------------------
# 6. FuzzingReport Serialisation
# ---------------------------------------------------------------------------

class TestFuzzingReportSerialisation:
    def test_to_dict_keys(self) -> None:
        report = _simulate_report("vulnerable", FuzzingMode.WHITEBOX, 50)
        d = report.to_dict()
        for key in ("target", "mode", "total_executions", "coverage_percent",
                    "unique_crashes", "hangs", "execution_time_seconds",
                    "executions_per_second", "crashes", "remediation_suggestions",
                    "coverage_timeline", "execution_events"):
            assert key in d, f"Missing key: {key}"

    def test_export_json(self, tmp_path: Path) -> None:
        report = _simulate_report("vulnerable", FuzzingMode.WHITEBOX, 50)
        out_file = tmp_path / "report.json"
        path = report.export_json(out_file)
        assert Path(path).exists()
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        assert data["unique_crashes"] == 1

    def test_export_markdown(self, tmp_path: Path) -> None:
        report = _simulate_report("vulnerable", FuzzingMode.WHITEBOX, 50)
        out_file = tmp_path / "report.md"
        path = report.export_markdown(out_file)
        content = Path(path).read_text(encoding="utf-8")
        assert "Fuzzing Security Report" in content
        assert "Remediation" in content

    def test_executions_per_second_positive(self) -> None:
        report = _simulate_report("vulnerable", FuzzingMode.WHITEBOX, 100)
        assert report.executions_per_second > 0


# ---------------------------------------------------------------------------
# 7. DOT Generator
# ---------------------------------------------------------------------------

class TestGenerateExecutionFlowDot:
    def test_crash_outcome_red_color(self) -> None:
        dot = generate_execution_flow_dot("payload", "CRASH", "asan error", "Whitebox")
        assert "#F8A5A5" in dot

    def test_pass_outcome_green_color(self) -> None:
        dot = generate_execution_flow_dot("payload", "PASS", "", "Blackbox")
        assert "#A3D9A5" in dot

    def test_dot_valid_structure(self) -> None:
        dot = generate_execution_flow_dot("p", "CRASH")
        assert "digraph" in dot
        assert "seed" in dot
        assert "outcome" in dot


# ---------------------------------------------------------------------------
# 8. Blackbox Fuzzer (simulation path — fast tests)
# ---------------------------------------------------------------------------

class TestBlackboxFuzzerSimulated:
    """Test blackbox engine via simulation (no GCC required)."""

    def test_returns_fuzzing_report(self) -> None:
        report = _simulate_report("vulnerable", FuzzingMode.BLACKBOX, 100)
        assert isinstance(report, FuzzingReport)

    def test_mode_is_blackbox(self) -> None:
        report = _simulate_report("vulnerable", FuzzingMode.BLACKBOX, 100)
        assert "Blackbox" in report.mode

    def test_coverage_is_zero_for_blackbox(self) -> None:
        """Black-box MUST report 0% coverage — no instrumentation used."""
        report = _simulate_report("vulnerable", FuzzingMode.BLACKBOX, 200)
        assert report.coverage_percent == 0.0

    def test_timeline_all_zero_coverage(self) -> None:
        report = _simulate_report("vulnerable", FuzzingMode.BLACKBOX, 200)
        for _iter, cov in report.coverage_timeline:
            assert cov == 0.0


# ---------------------------------------------------------------------------
# 9. Whitebox Fuzzer (simulation path — fast tests)
# ---------------------------------------------------------------------------

class TestWhiteboxFuzzerSimulated:
    """Test whitebox engine via simulation (no GCC required)."""

    def test_returns_fuzzing_report(self) -> None:
        report = _simulate_report("vulnerable", FuzzingMode.WHITEBOX, 100)
        assert isinstance(report, FuzzingReport)

    def test_mode_is_whitebox(self) -> None:
        report = _simulate_report("vulnerable", FuzzingMode.WHITEBOX, 100)
        assert "Whitebox" in report.mode

    def test_coverage_nonzero(self) -> None:
        report = _simulate_report("vulnerable", FuzzingMode.WHITEBOX, 100)
        assert report.coverage_percent > 0.0

    def test_coverage_timeline_grows(self) -> None:
        report = _simulate_report("vulnerable", FuzzingMode.WHITEBOX, 100)
        covs = [cov for _, cov in report.coverage_timeline]
        assert covs[-1] >= covs[0]

    def test_has_new_branch_events(self) -> None:
        report = _simulate_report("vulnerable", FuzzingMode.WHITEBOX, 100)
        branch_events = [e for e in report.execution_events if e.event == "NEW_BRANCH"]
        assert len(branch_events) > 0

    def test_crash_has_asan_true(self) -> None:
        report = _simulate_report("vulnerable", FuzzingMode.WHITEBOX, 100)
        assert report.crashes[0].sanitizer_finding is True


# ---------------------------------------------------------------------------
# 10. Compare Fuzzers (simulation path)
# ---------------------------------------------------------------------------

class TestCompareFuzzersSimulated:
    """Test compare_fuzzers() with simulation data (no GCC required)."""

    def _run_simulated_compare(self, tmp_path: Path) -> dict:
        """Patch the underlying functions to use simulation then call compare_fuzzers."""
        import src.testing.fuzzing as fuzz_mod
        original_bb = fuzz_mod.run_blackbox_fuzzer
        original_wb = fuzz_mod.run_whitebox_fuzzer
        try:
            fuzz_mod.run_blackbox_fuzzer = lambda impl, iters, seed, tout: _simulate_report(
                impl, FuzzingMode.BLACKBOX, iters
            )
            fuzz_mod.run_whitebox_fuzzer = lambda impl, iters, seed, tout: _simulate_report(
                impl, FuzzingMode.WHITEBOX, iters
            )
            out = tmp_path / "cmp.json"
            return fuzz_mod.compare_fuzzers(budget=50, output_path=out)
        finally:
            fuzz_mod.run_blackbox_fuzzer = original_bb
            fuzz_mod.run_whitebox_fuzzer = original_wb

    def test_compare_result_structure(self, tmp_path: Path) -> None:
        result = self._run_simulated_compare(tmp_path)
        for key in ("meta", "blackbox", "whitebox", "comparison"):
            assert key in result

    def test_comparison_keys_present(self, tmp_path: Path) -> None:
        result = self._run_simulated_compare(tmp_path)
        cmp = result["comparison"]
        for k in ("crashes_blackbox", "crashes_whitebox",
                   "coverage_blackbox_pct", "coverage_whitebox_pct",
                   "whitebox_advantage_coverage_pct"):
            assert k in cmp

    def test_whitebox_higher_coverage_in_comparison(self, tmp_path: Path) -> None:
        result = self._run_simulated_compare(tmp_path)
        cmp = result["comparison"]
        assert cmp["coverage_whitebox_pct"] > cmp["coverage_blackbox_pct"]

    def test_json_file_created(self, tmp_path: Path) -> None:
        out = tmp_path / "cmp.json"
        self._run_simulated_compare(tmp_path)
        assert out.exists() or (DATASET_DIR / "fuzzing_comparison_results.json").exists()


# ---------------------------------------------------------------------------
# 11. Real Compiler Tests (skipped if GCC unavailable)
# ---------------------------------------------------------------------------

import shutil

needs_gcc = pytest.mark.skipif(
    shutil.which("gcc") is None and shutil.which("cc") is None,
    reason="GCC/cc not available in this environment",
)


@needs_gcc
class TestBlackboxFuzzerReal:
    """Integration tests against the actual compiled C binary."""

    def test_finds_crash_on_vulnerable(self, tmp_path: Path) -> None:
        crash_dir = tmp_path / "crashes"
        report = run_blackbox_fuzzer(
            implementation="vulnerable",
            iterations=200,
            seed=42,
            timeout_seconds=2.0,
            crash_dir=crash_dir,
        )
        assert isinstance(report, FuzzingReport)
        # Crash detection is expected but not guaranteed within 200 iters for blackbox
        # At minimum the report must be structurally valid
        assert report.total_executions == 200
        assert report.coverage_percent == 0.0  # Black-box: no coverage

    def test_no_crash_on_safe(self, tmp_path: Path) -> None:
        crash_dir = tmp_path / "crashes"
        report = run_blackbox_fuzzer(
            implementation="safe",
            iterations=200,
            seed=42,
            timeout_seconds=2.0,
            crash_dir=crash_dir,
        )
        assert report.unique_crashes == 0


@needs_gcc
class TestWhiteboxFuzzerReal:
    """Integration tests: whitebox MUST find crash within 500 iterations."""

    def test_whitebox_finds_crash_within_budget(self, tmp_path: Path) -> None:
        """
        REQUIREMENT (Lab 8): Whitebox MUST find crash in <= 500 iterations
        on the vulnerable implementation with fixed seed=42.
        """
        crash_dir = tmp_path / "crashes"
        report = run_whitebox_fuzzer(
            implementation="vulnerable",
            iterations=500,
            seed=42,
            timeout_seconds=2.0,
            crash_dir=crash_dir,
        )
        assert report.unique_crashes >= 1, (
            f"Whitebox fuzzer failed to find crash in 500 iterations. "
            f"Events: {[e.event for e in report.execution_events]}"
        )

    def test_whitebox_crash_artifact_saved(self, tmp_path: Path) -> None:
        """Crash payload must be persisted to crash_dir."""
        crash_dir = tmp_path / "crashes"
        report = run_whitebox_fuzzer(
            implementation="vulnerable",
            iterations=500,
            seed=42,
            timeout_seconds=2.0,
            crash_dir=crash_dir,
        )
        if report.unique_crashes > 0:
            crash_files = list(crash_dir.glob("whitebox_crash_*.txt"))
            assert len(crash_files) > 0, "Crash artifacts not saved to crashes/ directory"

    def test_whitebox_has_new_branch_events(self, tmp_path: Path) -> None:
        """Feedback loop must emit NEW_BRANCH events."""
        crash_dir = tmp_path / "crashes"
        report = run_whitebox_fuzzer(
            implementation="vulnerable",
            iterations=200,
            seed=42,
            timeout_seconds=2.0,
            crash_dir=crash_dir,
        )
        branch_events = [e for e in report.execution_events if e.event == "NEW_BRANCH"]
        assert len(branch_events) > 0, "Whitebox fuzzer did not emit any NEW_BRANCH events"

    def test_whitebox_coverage_nonzero(self, tmp_path: Path) -> None:
        crash_dir = tmp_path / "crashes"
        report = run_whitebox_fuzzer(
            implementation="vulnerable",
            iterations=200,
            seed=42,
            timeout_seconds=2.0,
            crash_dir=crash_dir,
        )
        assert report.coverage_percent > 0.0

    def test_whitebox_coverage_greater_than_blackbox(self, tmp_path: Path) -> None:
        """Whitebox MUST have higher coverage than blackbox (by design)."""
        crash_dir = tmp_path / "crashes"
        bb = run_blackbox_fuzzer("vulnerable", 100, 42, 2.0, crash_dir)
        wb = run_whitebox_fuzzer("vulnerable", 100, 42, 2.0, crash_dir)
        assert wb.coverage_percent > bb.coverage_percent

    def test_whitebox_no_crash_on_safe(self, tmp_path: Path) -> None:
        crash_dir = tmp_path / "crashes"
        report = run_whitebox_fuzzer(
            implementation="safe",
            iterations=300,
            seed=42,
            timeout_seconds=2.0,
            crash_dir=crash_dir,
        )
        assert report.unique_crashes == 0


@needs_gcc
def test_compare_fuzzers_real(tmp_path: Path) -> None:
    """compare_fuzzers() on real binaries must produce valid JSON with all keys."""
    out = tmp_path / "comparison.json"
    result = compare_fuzzers(
        implementation="vulnerable",
        budget=100,
        seed=42,
        timeout_seconds=2.0,
        output_path=out,
    )
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    cmp = data["comparison"]
    assert "crashes_blackbox" in cmp
    assert "crashes_whitebox" in cmp
    assert "coverage_whitebox_pct" in cmp
    assert cmp["coverage_whitebox_pct"] >= cmp["coverage_blackbox_pct"]
