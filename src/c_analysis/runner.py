"""Run reproducible analysis checks for the C buffer-copy example."""

from __future__ import annotations

import importlib
import json
import re
import shlex
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from src.c_analysis.model import (
    BUFFER_CAPACITY,
    SAFETY_CONSTRAINTS,
    find_bounded_counterexample,
    validate_model,
)

CheckStatus = Literal["PASS", "FINDING", "UNAVAILABLE", "ERROR"]
PROJECT_ROOT = Path(__file__).resolve().parents[2]
C_ROOT = PROJECT_ROOT / "csrc"
REPORT_PATH = PROJECT_ROOT / "reports" / "c_analysis" / "latest_report.json"
ANALYSIS_LENGTHS = range(-32, 33)


@dataclass
class CheckResult:
    name: str
    status: CheckStatus
    summary: str
    command: str = ""
    details: str = ""


@dataclass
class AnalysisReport:
    generated_at: str
    checks: list[CheckResult] = field(default_factory=list)
    report_path: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "generated_at": self.generated_at,
            "checks": [asdict(check) for check in self.checks],
            "report_path": self.report_path,
            "scope": (
                "Bounded buffer-copy model, GCC analyzer, optional CBMC, "
                "sanitizer demonstration, and deterministic mutation fuzzing."
            ),
            "model_constraints": list(SAFETY_CONSTRAINTS),
        }


def _format_command(command: list[str]) -> str:
    return shlex.join(command)


def _run_command(
    command: list[str],
    timeout_seconds: int = 30,
) -> tuple[int | None, str, str, str | None]:
    try:
        completed = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
    except FileNotFoundError as exc:
        return None, "", "", str(exc)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else exc.stdout or ""
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else exc.stderr or ""
        return None, stdout, stderr, f"Command timed out after {timeout_seconds} seconds."
    except OSError as exc:
        return None, "", "", f"Could not start command: {exc}"

    return completed.returncode, completed.stdout, completed.stderr, None


def _check_formal_model(report: AnalysisReport) -> None:
    model_errors = validate_model()
    if model_errors:
        report.checks.append(
            CheckResult(
                name="Formal state model",
                status="ERROR",
                summary="The state model is structurally invalid.",
                details="\n".join(model_errors),
            )
        )
        return

    vulnerable = find_bounded_counterexample(
        "vulnerable",
        ANALYSIS_LENGTHS,
    )
    safe = find_bounded_counterexample("safe", ANALYSIS_LENGTHS)
    if vulnerable is None:
        report.checks.append(
            CheckResult(
                name="Vulnerable model counterexample",
                status="ERROR",
                summary="No expected counterexample was found in the bounded domain.",
                details=f"Checked lengths {ANALYSIS_LENGTHS.start} through "
                f"{ANALYSIS_LENGTHS.stop - 1}.",
            )
        )
    else:
        report.checks.append(
            CheckResult(
                name="Vulnerable model counterexample",
                status="FINDING",
                summary=(
                    f"Found length={vulnerable.length}: the vulnerable guard "
                    "allows an invalid copy."
                ),
                details=(
                    f"Trace: {' -> '.join(vulnerable.trace)}\n"
                    f"Violations: {'; '.join(vulnerable.violations)}\n"
                    f"Bounded lengths: {ANALYSIS_LENGTHS.start} through "
                    f"{ANALYSIS_LENGTHS.stop - 1}; source and destination sizes "
                    f"from 0, 1, 8, and {BUFFER_CAPACITY}."
                ),
            )
        )

    if safe is None:
        report.checks.append(
            CheckResult(
                name="Safe model bounded check",
                status="PASS",
                summary="No safety-constraint violation found in the bounded domain.",
                details=(
                    f"Checked lengths {ANALYSIS_LENGTHS.start} through "
                    f"{ANALYSIS_LENGTHS.stop - 1} and sizes 0, 1, 8, "
                    f"and {BUFFER_CAPACITY}. This is bounded evidence, not "
                    "a proof for every possible C execution."
                ),
            )
        )
    else:
        report.checks.append(
            CheckResult(
                name="Safe model bounded check",
                status="FINDING",
                summary=f"Found an invalid safe-model copy at length={safe.length}.",
                details="\n".join(safe.violations),
            )
        )

    _run_smt_model_checking(report)


def _run_smt_model_checking(report: AnalysisReport) -> None:
    try:
        z3 = importlib.import_module("z3")
    except ModuleNotFoundError:
        report.checks.append(
            CheckResult(
                name="Z3 SMT guard verification",
                status="UNAVAILABLE",
                summary=(
                    "z3-solver is not installed; only the finite bounded "
                    "Python model ran."
                ),
            )
        )
        return

    length = z3.Int("copy_length")
    source_size = z3.Int("source_size")
    destination_capacity = z3.Int("destination_capacity")
    in_c_domain = z3.And(
        length >= -(2**31),
        length <= 2**31 - 1,
        source_size >= 0,
        source_size <= BUFFER_CAPACITY,
        destination_capacity >= 0,
        destination_capacity <= BUFFER_CAPACITY,
    )
    invalid_copy = z3.Or(
        length < 0,
        length > source_size,
        length > destination_capacity,
    )

    vulnerable_solver = z3.Solver()
    vulnerable_solver.add(
        in_c_domain,
        source_size == BUFFER_CAPACITY,
        destination_capacity == BUFFER_CAPACITY,
        length <= destination_capacity,
        length == -1,
        invalid_copy,
    )
    vulnerable_result = vulnerable_solver.check()
    if vulnerable_result == z3.sat:
        counterexample = vulnerable_solver.model()
        vulnerable_status: CheckStatus = "FINDING"
        vulnerable_summary = (
            "Z3 found an invalid copy admitted by the vulnerable guard."
        )
        vulnerable_details = (
            f"length={counterexample.eval(length)}, "
            f"source_size={counterexample.eval(source_size)}, "
            f"destination_capacity="
            f"{counterexample.eval(destination_capacity)}\n"
            f"Fixed harness capacity: {BUFFER_CAPACITY} bytes per buffer.\n"
            "Query: signed length == -1 AND length <= destination capacity "
            "AND (length < 0 OR length > source size OR "
            "length > destination capacity)."
        )
    elif vulnerable_result == z3.unsat:
        vulnerable_status = "ERROR"
        vulnerable_summary = (
            "Z3 did not find the expected vulnerable-guard counterexample."
        )
        vulnerable_details = "The vulnerable guard query was unsatisfiable."
    else:
        vulnerable_status = "ERROR"
        vulnerable_summary = "Z3 could not decide the vulnerable-guard query."
        vulnerable_details = str(vulnerable_result)

    report.checks.append(
        CheckResult(
            name="Z3 vulnerable guard counterexample",
            status=vulnerable_status,
            summary=vulnerable_summary,
            details=vulnerable_details,
        )
    )

    safe_solver = z3.Solver()
    safe_guard = z3.And(
        length >= 0,
        length <= source_size,
        length <= destination_capacity,
    )
    safe_solver.add(in_c_domain, safe_guard, invalid_copy)
    safe_result = safe_solver.check()
    if safe_result == z3.unsat:
        safe_status: CheckStatus = "PASS"
        safe_summary = (
            "Z3 proved the safe guard admits no invalid length in the modeled "
            "32-bit signed-integer and buffer-size domain."
        )
    elif safe_result == z3.sat:
        safe_status = "FINDING"
        safe_summary = "Z3 found an invalid copy admitted by the safe guard."
    else:
        safe_status = "ERROR"
        safe_summary = "Z3 could not decide the safe-guard query."

    report.checks.append(
        CheckResult(
            name="Z3 safe guard verification",
            status=safe_status,
            summary=safe_summary,
            details=(
                "SMT verifies the modeled guard conditions, not the compiled "
                "C binary or pointer behavior."
                if safe_result == z3.unsat
                else str(safe_result)
            ),
        )
    )


def _run_gcc_analysis(
    report: AnalysisReport,
    compiler: str,
    work_dir: Path,
) -> None:
    compiler_path = shutil.which(compiler)
    if compiler_path is None:
        report.checks.append(
            CheckResult(
                name="GCC static analysis",
                status="UNAVAILABLE",
                summary=f"C compiler '{compiler}' was not found on PATH.",
            )
        )
        return

    for implementation in ("vulnerable", "safe"):
        source = C_ROOT / implementation / "buffer_copy.c"
        object_path = work_dir / f"{implementation}.o"
        command = [
            compiler_path,
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Wconversion",
            "-Wsign-conversion",
            "-fanalyzer",
            "-I",
            str(C_ROOT / "include"),
            "-c",
            str(source),
            "-o",
            str(object_path),
        ]
        return_code, stdout, stderr, error = _run_command(command)
        diagnostics = "\n".join(
            part for part in (stdout, stderr) if part
        ).strip()
        if error:
            status: CheckStatus = "ERROR"
            summary = error
        elif return_code != 0:
            status = "ERROR"
            summary = (
                f"GCC analysis failed for the {implementation} implementation "
                f"with exit code {return_code}."
            )
        elif re.search(r"\b(?:warning|error):", diagnostics, re.IGNORECASE):
            status = "FINDING"
            summary = f"GCC reported diagnostics in the {implementation} implementation."
        else:
            status = "PASS"
            summary = (
                f"GCC compiled the {implementation} implementation with "
                "warnings and analyzer checks enabled."
            )

        report.checks.append(
            CheckResult(
                name=f"GCC static analysis ({implementation})",
                status=status,
                summary=summary,
                command=_format_command(command),
                details=diagnostics,
            )
        )


def _run_cbmc(report: AnalysisReport) -> None:
    cbmc = shutil.which("cbmc")
    if cbmc is None:
        report.checks.append(
            CheckResult(
                name="CBMC bounded model checking",
                status="UNAVAILABLE",
                summary=(
                    "CBMC is not installed. The bounded Python model and GCC "
                    "checks still ran; no CBMC result is claimed."
                ),
            )
        )
        return

    harness = C_ROOT / "harness" / "cbmc_buffer_copy_harness.c"
    for implementation in ("vulnerable", "safe"):
        source = C_ROOT / implementation / "buffer_copy.c"
        command = [
            cbmc,
            str(source),
            str(harness),
            "--bounds-check",
            "--pointer-check",
            "--signed-overflow-check",
            "--trace",
        ]
        return_code, stdout, stderr, error = _run_command(
            command,
            timeout_seconds=60,
        )
        output = "\n".join(part for part in (stdout, stderr) if part).strip()
        if error:
            status: CheckStatus = "ERROR"
            summary = error
        elif "VERIFICATION FAILED" in output:
            status = "FINDING"
            summary = f"CBMC found a counterexample in the {implementation} implementation."
        elif "VERIFICATION SUCCESSFUL" in output:
            status = "PASS"
            summary = f"CBMC verified the {implementation} harness."
        else:
            status = "ERROR"
            summary = f"CBMC exited with status {return_code} without a recognized result."

        report.checks.append(
            CheckResult(
                name=f"CBMC ({implementation})",
                status=status,
                summary=summary,
                command=_format_command(command),
                details=output,
            )
        )


def _compile(
    compiler_path: str,
    source_files: list[Path],
    output_path: Path,
    sanitizer: bool,
) -> tuple[list[str], int | None, str, str, str | None]:
    command = [
        compiler_path,
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Wconversion",
        "-Wsign-conversion",
        "-I",
        str(C_ROOT / "include"),
    ]
    if sanitizer:
        command.extend(("-fsanitize=address,undefined", "-fno-omit-frame-pointer"))
    command.extend(str(source) for source in source_files)
    command.extend(("-o", str(output_path)))
    return command, *_run_command(command)


def _sanitizer_unavailable(details: str) -> bool:
    unsupported_markers = (
        "cannot find -lasan",
        "cannot find -lubsan",
        "unrecognized command-line option",
        "unsupported option",
    )
    lowered = details.lower()
    return any(marker in lowered for marker in unsupported_markers)


def _run_native_boundary_tests(
    report: AnalysisReport,
    compiler_path: str,
    work_dir: Path,
) -> None:
    outcomes = []
    unexpected_failure = False

    for implementation in ("vulnerable", "safe"):
        source = C_ROOT / implementation / "buffer_copy.c"
        binary = work_dir / f"buffer_copy_native_{implementation}.exe"
        _, return_code, _, stderr, error = _compile(
            compiler_path,
            [source, C_ROOT / "cli" / "buffer_copy_cli.c"],
            binary,
            sanitizer=False,
        )
        if error or return_code != 0:
            outcomes.append(
                f"{implementation}: build failed: "
                f"{error or stderr or return_code}"
            )
            unexpected_failure = True
            continue

        lengths = ("-1",) if implementation == "vulnerable" else (
            "-1",
            "17",
            "0",
            str(BUFFER_CAPACITY),
        )
        for length in lengths:
            run_code, run_stdout, run_stderr, run_error = _run_command(
                [str(binary), length],
                timeout_seconds=10,
            )
            output = "\n".join(
                part for part in (run_stdout, run_stderr) if part
            ).strip()
            outcomes.append(
                f"{implementation}, length={length}, exit={run_code}\n{output}"
            )
            expected_code = (
                None
                if implementation == "vulnerable"
                else 0
                if length in {"0", str(BUFFER_CAPACITY)}
                else 2
            )
            if run_error or (
                expected_code is None and run_code == 0
            ) or (
                expected_code is not None and run_code != expected_code
            ):
                unexpected_failure = True

    if unexpected_failure:
        status: CheckStatus = "ERROR"
        summary = "Native boundary executions did not match the expected outcomes."
    else:
        status = "FINDING"
        summary = (
            "The vulnerable binary failed on a negative length while the safe "
            "binary rejected invalid inputs and accepted valid boundaries. "
            "These native runs are not sanitizer-instrumented."
        )

    report.checks.append(
        CheckResult(
            name="Native dynamic boundary tests",
            status=status,
            summary=summary,
            details="\n".join(outcomes),
        )
    )


def _run_dynamic_analysis(
    report: AnalysisReport,
    compiler: str,
    work_dir: Path,
) -> None:
    compiler_path = shutil.which(compiler)
    if compiler_path is None:
        report.checks.append(
            CheckResult(
                name="C dynamic analysis",
                status="UNAVAILABLE",
                summary=f"C compiler '{compiler}' was not found on PATH.",
            )
        )
        return

    sanitizer_unavailable = False
    for implementation in ("vulnerable", "safe"):
        source = C_ROOT / implementation / "buffer_copy.c"
        binary = work_dir / f"buffer_copy_{implementation}.exe"
        command, return_code, stdout, stderr, error = _compile(
            compiler_path,
            [source, C_ROOT / "cli" / "buffer_copy_cli.c"],
            binary,
            sanitizer=True,
        )
        if error or return_code != 0:
            build_details = "\n".join(
                part for part in (stdout, stderr, error or "") if part
            ).strip()
            unavailable = _sanitizer_unavailable(build_details)
            sanitizer_unavailable = sanitizer_unavailable or unavailable
            report.checks.append(
                CheckResult(
                    name=f"Sanitizer build ({implementation})",
                    status=(
                        "UNAVAILABLE"
                        if unavailable or error and "not found" in error.lower()
                        else "ERROR"
                    ),
                    summary=(
                        "The installed compiler does not provide the required "
                        "sanitizer runtime."
                        if unavailable
                        else error
                        or f"Sanitizer build failed with exit code {return_code}."
                    ),
                    command=_format_command(command),
                    details=build_details,
                )
            )
            continue

        lengths = ("-1",) if implementation == "vulnerable" else (
            "-1",
            "17",
            "0",
            str(BUFFER_CAPACITY),
        )
        outputs = []
        unexpected_failure = False
        for length in lengths:
            run_command = [str(binary), length]
            run_code, run_stdout, run_stderr, run_error = _run_command(
                run_command,
                timeout_seconds=10,
            )
            output = "\n".join(
                part for part in (run_stdout, run_stderr) if part
            ).strip()
            outputs.append(f"length={length}, exit={run_code}\n{output}")
            if (
                run_error
                or (
                    implementation == "safe"
                    and run_code
                    != (0 if length in {"0", str(BUFFER_CAPACITY)} else 2)
                )
                or (implementation == "vulnerable" and run_code == 0)
            ):
                unexpected_failure = True

        report.checks.append(
            CheckResult(
                name=f"Sanitizer runtime ({implementation})",
                status=(
                    "ERROR"
                    if unexpected_failure
                    else "FINDING"
                    if implementation == "vulnerable"
                    else "PASS"
                ),
                summary=(
                    "The invalid negative length was exercised against the vulnerable "
                    "copy routine."
                    if implementation == "vulnerable" and not unexpected_failure
                    else "The safe implementation rejected invalid lengths and copied valid boundaries."
                    if not unexpected_failure
                    else "The sanitizer execution did not produce the expected result."
                ),
                command=_format_command(command),
                details="\n".join(outputs),
            )
        )

    if sanitizer_unavailable:
        _run_native_boundary_tests(report, compiler_path, work_dir)


def _run_fuzzing(
    report: AnalysisReport,
    compiler: str,
    work_dir: Path,
    iterations: int,
    seed: int,
) -> None:
    compiler_path = shutil.which(compiler)
    if compiler_path is None:
        report.checks.append(
            CheckResult(
                name="Sanitizer fuzzing",
                status="UNAVAILABLE",
                summary=f"C compiler '{compiler}' was not found on PATH.",
            )
        )
        return

    source_files = [
        C_ROOT / "safe" / "buffer_copy.c",
        C_ROOT / "harness" / "fuzz_buffer_copy.c",
    ]
    binary = work_dir / "fuzz_buffer_copy.exe"
    command, return_code, stdout, stderr, error = _compile(
        compiler_path,
        source_files,
        binary,
        sanitizer=True,
    )
    if error or return_code != 0:
        build_details = "\n".join(
            part for part in (stdout, stderr, error or "") if part
        ).strip()
        sanitizer_unavailable = _sanitizer_unavailable(build_details)
        if sanitizer_unavailable:
            report.checks.append(
                CheckResult(
                    name="Sanitizer fuzzing",
                    status="UNAVAILABLE",
                    summary=(
                        "The installed compiler cannot link ASan/UBSan runtimes; "
                        "the deterministic fuzzer will run without sanitizers."
                    ),
                    command=_format_command(command),
                    details=build_details,
                )
            )
            command, return_code, stdout, stderr, error = _compile(
                compiler_path,
                source_files,
                binary,
                sanitizer=False,
            )
            if error or return_code != 0:
                report.checks.append(
                    CheckResult(
                        name="Deterministic mutation fuzzing",
                        status="ERROR",
                        summary=error or f"Fuzz harness build failed with exit code {return_code}.",
                        command=_format_command(command),
                        details="\n".join(
                            part for part in (stdout, stderr) if part
                        ).strip(),
                    )
                )
                return
            sanitized = False
        else:
            report.checks.append(
                CheckResult(
                    name="Sanitizer fuzzing",
                    status="ERROR",
                    summary=error or f"Fuzz harness build failed with exit code {return_code}.",
                    command=_format_command(command),
                    details=build_details,
                )
            )
            return
    else:
        sanitized = True

    run_command = [str(binary), str(iterations), str(seed)]
    run_code, run_stdout, run_stderr, run_error = _run_command(
        run_command,
        timeout_seconds=30,
    )
    output = "\n".join(part for part in (run_stdout, run_stderr) if part).strip()
    if run_error:
        status: CheckStatus = "ERROR"
        summary = run_error
    elif run_code == 0:
        status = "PASS"
        summary = (
            f"Completed {iterations} deterministic mutation-fuzz iterations "
            f"with seed {seed}"
            f"{' under ASan/UBSan' if sanitized else ' without sanitizers'}."
        )
    else:
        status = "FINDING"
        summary = f"Fuzzing found a crash or assertion failure (exit code {run_code})."

    report.checks.append(
        CheckResult(
            name=(
                "Sanitizer fuzzing"
                if sanitized
                else "Deterministic mutation fuzzing"
            ),
            status=status,
            summary=summary,
            command=_format_command(run_command),
            details=output,
        )
    )


def _persist_report(report: AnalysisReport, report_path: Path) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report.report_path = str(report_path)
    report_path.write_text(
        json.dumps(report.to_dict(), indent=2),
        encoding="utf-8",
    )


def run_c_analysis(
    compiler: str = "gcc",
    iterations: int = 10_000,
    seed: int = 0xC0FFEE,
    report_path: Path = REPORT_PATH,
) -> AnalysisReport:
    """Run model, compiler, BMC, sanitizer, and fuzz checks and save a report."""
    if not 1 <= iterations <= 1_000_000:
        raise ValueError("iterations must be between 1 and 1,000,000")
    if not 0 <= seed <= 0xFFFFFFFF:
        raise ValueError("seed must be between 0 and 2**32 - 1")

    report = AnalysisReport(
        generated_at=datetime.now(UTC).isoformat(),
    )
    _check_formal_model(report)

    with tempfile.TemporaryDirectory(prefix="lms-c-analysis-") as temporary_dir:
        work_dir = Path(temporary_dir)
        _run_gcc_analysis(report, compiler, work_dir)
        _run_cbmc(report)
        _run_dynamic_analysis(report, compiler, work_dir)
        _run_fuzzing(report, compiler, work_dir, iterations, seed)

    _persist_report(report, report_path)
    return report
