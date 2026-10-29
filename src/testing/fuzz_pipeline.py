"""Reproducible fuzzing pipeline for the LMS project.

The pipeline runs three families of fuzzing and reports them together:

* black-box fuzzing of the compiled C CLI with bounded seed inputs;
* white-box fuzzing of the C copy routine through a deterministic harness;
* white-box property/invariant fuzzing of the Python LMS modules.

Every run is reproducible: the same ``seed`` and ``iterations`` produce the
same corpus and the same coverage counters.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.c_analysis.runner import run_c_analysis
from src.modules.authentication import PASSWORD_HASH_ITERATIONS_ENV
from src.testing.fuzzing import run_fuzzing

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REPORT_PATH = PROJECT_ROOT / "reports" / "fuzzing" / "latest_report.json"
DEFAULT_EXPORT_DIR = PROJECT_ROOT / "reports" / "fuzzing"
DEFAULT_ITERATIONS = 2000
DEFAULT_SEED = 0xC0FFEE
MAX_ITERATIONS = 1_000_000
MAX_SEED = 0xFFFFFFFF

#: Password hashing at the production strength (600k PBKDF2 rounds) dominates the
#: runtime of the authentication fuzz target. The fuzz invariants do not depend on
#: hash strength, so a cheaper cost is used for the whole Python fuzzing stage.
PYTHON_FUZZ_HASH_ITERATIONS = 10_000


@dataclass
class FuzzStage:
    """One fuzzing stage with its own seed data, coverage, and verdict."""

    key: str
    name: str
    mode: str
    status: str
    summary: str
    iterations: int = 0
    coverage: dict[str, Any] = field(default_factory=dict)
    seed_data: list[Any] = field(default_factory=list)
    details: list[str] = field(default_factory=list)


@dataclass
class FuzzPipelineResult:
    iterations: int
    seed: int
    generated_at: str
    stages: list[FuzzStage] = field(default_factory=list)
    report_path: str = ""

    @property
    def findings(self) -> list[str]:
        return [
            f"{stage.name}: {detail}"
            for stage in self.stages
            for detail in stage.details
        ]

    @property
    def summary(self) -> dict[str, int]:
        counts = {"PASS": 0, "FINDING": 0, "UNAVAILABLE": 0, "ERROR": 0}
        for stage in self.stages:
            counts[stage.status] = counts.get(stage.status, 0) + 1
        counts["stages_total"] = len(self.stages)
        counts["steps_total"] = sum(
            stage.iterations or 0 for stage in self.stages
        )
        return counts

    @property
    def passed(self) -> bool:
        return self.summary["FINDING"] == 0 and self.summary["ERROR"] == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "iterations": self.iterations,
            "seed": self.seed,
            "generated_at": self.generated_at,
            "passed": self.passed,
            "summary": self.summary,
            "stages": [asdict(stage) for stage in self.stages],
            "findings": self.findings,
            "report_path": self.report_path,
        }


def _black_box_stage(black_box: dict[str, Any]) -> FuzzStage:
    cases: list[dict[str, Any]] = list(black_box.get("cases") or [])
    coverage: dict[str, Any] = dict(black_box.get("coverage") or {})

    if any(case.get("execution_error") for case in cases):
        status = "ERROR"
    elif any(case.get("timed_out") or not case.get("passed") for case in cases):
        status = "FINDING"
    else:
        status = "PASS"

    passed = int(coverage.get("cases_passed", 0))
    total = int(coverage.get("cases_total", len(cases)))
    classes = len(coverage.get("input_classes") or [])

    if status == "PASS":
        summary = (
            f"{passed}/{total} black-box CLI inputs matched the expected exit "
            f"codes, covering {classes} input classes."
        )
    elif status == "FINDING":
        summary = (
            f"{total - passed}/{total} black-box CLI inputs deviated from the "
            "expected exit codes (crash, hang, or unexpected result)."
        )
    else:
        summary = "A black-box CLI case could not be executed."

    return FuzzStage(
        key="black_box",
        name="Black-box CLI boundary fuzzing",
        mode=str(black_box.get("mode", "Black-box CLI boundary testing")),
        status=status,
        summary=summary,
        iterations=total,
        coverage=coverage,
        seed_data=list(black_box.get("seed_data") or []),
        details=[
            f"input={case.get('input')!r} expected_exit={case.get('expected_exit')} "
            f"actual_exit={case.get('actual_exit')} "
            f"timed_out={bool(case.get('timed_out'))}"
            for case in cases
            if not case.get("passed")
        ],
    )


def _white_box_stage(white_box: dict[str, Any]) -> FuzzStage:
    status = str(white_box.get("status", "ERROR"))
    coverage: dict[str, Any] = dict(white_box.get("coverage") or {})
    iterations = int(white_box.get("iterations") or 0)
    covered = int(coverage.get("input_classes_covered", 0))
    total_classes = int(coverage.get("input_classes_total", 0))

    if status == "PASS":
        summary = (
            f"Completed {iterations} deterministic direct-call iterations with "
            f"seed {white_box.get('seed')}, covering {covered}/{total_classes} "
            "input classes without a crash, sanitizer report, or hang."
        )
    elif status == "FINDING":
        summary = (
            "The white-box fuzzer detected a crash, sanitizer report, or hang "
            f"within {iterations} iterations."
        )
    elif status == "UNAVAILABLE":
        summary = str(white_box.get("summary", "White-box fuzzing is unavailable."))
    else:
        summary = "The white-box fuzz harness could not be built or executed."

    return FuzzStage(
        key="white_box",
        name="White-box deterministic fuzzing",
        mode=str(white_box.get("mode", "White-box deterministic direct-call fuzzing")),
        status=status,
        summary=summary,
        iterations=iterations,
        coverage=coverage,
        seed_data=list(white_box.get("seed_data") or []),
        details=[]
        if status in {"PASS", "UNAVAILABLE"}
        else [f"White-box fuzzing reported {status}."],
    )


def _c_stages(iterations: int, seed: int) -> list[FuzzStage]:
    try:
        report = run_c_analysis(iterations=iterations, seed=seed)
    except (OSError, ValueError) as exc:
        return [
            FuzzStage(
                key="black_box",
                name="Black-box CLI boundary fuzzing",
                mode="Black-box CLI boundary testing",
                status="ERROR",
                summary=f"The C analysis runner failed: {exc}",
                details=[str(exc)],
            ),
            FuzzStage(
                key="white_box",
                name="White-box deterministic fuzzing",
                mode="White-box deterministic direct-call fuzzing",
                status="ERROR",
                summary=f"The C analysis runner failed: {exc}",
                details=[str(exc)],
            ),
        ]

    fuzzing: dict[str, Any] = dict(report.fuzzing)
    black_box: dict[str, Any] = fuzzing.get("black_box") or {}
    white_box: dict[str, Any] = fuzzing.get("white_box") or {}

    stages: list[FuzzStage] = []
    if black_box:
        stages.append(_black_box_stage(black_box))
    else:
        stages.append(
            FuzzStage(
                key="black_box",
                name="Black-box CLI boundary fuzzing",
                mode="Black-box CLI boundary testing",
                status="UNAVAILABLE",
                summary=(
                    "No black-box cases were produced; the C toolchain is not "
                    "available in this environment."
                ),
            )
        )

    if white_box:
        stages.append(_white_box_stage(white_box))
    else:
        stages.append(
            FuzzStage(
                key="white_box",
                name="White-box deterministic fuzzing",
                mode="White-box deterministic direct-call fuzzing",
                status="UNAVAILABLE",
                summary=(
                    "No white-box fuzz run was produced; the C toolchain is not "
                    "available in this environment."
                ),
            )
        )

    return stages


def _python_stages(iterations: int, seed: int) -> list[FuzzStage]:
    stages: list[FuzzStage] = []
    for row in run_fuzzing(iterations=iterations, seed=seed):
        raw_details = str(row.get("details") or "")
        stages.append(
            FuzzStage(
                key=f"python:{row.get('name')}",
                name=str(row.get("name")),
                mode="White-box property and invariant fuzzing (Python)",
                status=str(row.get("status")),
                summary=str(row.get("summary")),
                iterations=iterations,
                coverage={"target": str(row.get("name"))},
                seed_data=[],
                details=[
                    line for line in raw_details.splitlines() if line.strip()
                ],
            )
        )
    return stages


def _python_stages_with_fast_hashing(
    iterations: int,
    seed: int,
) -> list[FuzzStage]:
    """Run the Python fuzz targets with a cheaper but deterministic PBKDF2 cost.

    The production hash strength makes ``fuzz_authentication`` unbearably slow,
    so the round count is lowered for the duration of the stage and the previous
    environment value is always restored afterwards.
    """
    previous = os.environ.get(PASSWORD_HASH_ITERATIONS_ENV)
    os.environ[PASSWORD_HASH_ITERATIONS_ENV] = str(PYTHON_FUZZ_HASH_ITERATIONS)
    try:
        return _python_stages(iterations, seed)
    finally:
        if previous is None:
            os.environ.pop(PASSWORD_HASH_ITERATIONS_ENV, None)
        else:
            os.environ[PASSWORD_HASH_ITERATIONS_ENV] = previous


def run_fuzz_pipeline(
    iterations: int = DEFAULT_ITERATIONS,
    seed: int = DEFAULT_SEED,
    report_path: Path | str | None = None,
    export_dir: Path | str | None = None,
    export: bool = True,
) -> FuzzPipelineResult:
    """Run black-box, white-box, and Python fuzzing with one reproducible seed."""
    if not 1 <= iterations <= MAX_ITERATIONS:
        raise ValueError("iterations must be between 1 and 1,000,000")
    if not 0 <= seed <= MAX_SEED:
        raise ValueError("seed must be between 0 and 2**32 - 1")

    result = FuzzPipelineResult(
        iterations=iterations,
        seed=seed,
        generated_at=datetime.now(UTC).isoformat(),
    )
    result.stages.extend(_c_stages(iterations, seed))
    result.stages.extend(_python_stages_with_fast_hashing(iterations, seed))

    path = Path(report_path) if report_path is not None else DEFAULT_REPORT_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    result.report_path = str(path)
    path.write_text(
        json.dumps(result.to_dict(), indent=2),
        encoding="utf-8",
    )

    if export:
        from src.testing.fuzzing_report import export_fuzzing_report

        export_fuzzing_report(
            result,
            Path(export_dir) if export_dir is not None else DEFAULT_EXPORT_DIR,
        )

    return result
