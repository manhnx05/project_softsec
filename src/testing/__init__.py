"""Testing and Fuzzing Framework package."""

from src.testing.dynamic import run_coverage, run_pytest
from src.testing.fuzzing import (
    CRASHES_DIR,
    DATASET_DIR,
    CrashWitness,
    ExecutionEvent,
    Fuzzer,
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
    test_login_input_never_crashes,
)
from src.testing.static import run_mypy, run_ruff

__all__ = [
    "run_pytest",
    "run_coverage",
    "run_ruff",
    "run_mypy",
    # Core types
    "Fuzzer",
    "FuzzingMode",
    "FuzzingReport",
    "CrashWitness",
    "ExecutionEvent",
    # Engine functions
    "run_blackbox_fuzzer",
    "run_whitebox_fuzzer",
    "compare_fuzzers",
    # Utilities
    "load_seeds",
    "mutate_payload",
    "minimize_crash_payload",
    "generate_execution_flow_dot",
    # Internal (exported for test suite)
    "_CoverageTracker",
    "_simulate_report",
    # Paths
    "CRASHES_DIR",
    "DATASET_DIR",
    # Hypothesis test
    "test_login_input_never_crashes",
]
