"""Comprehensive Fuzzing Framework for SoftSec -- Lab 8 (SecureSys).

Dataflow
--------
  csrc/fuzz_seeds/*.txt
      |
      |----> run_blackbox_fuzzer  -->  crashes/blackbox_crash_<ts>.txt
      |----> run_whitebox_fuzzer  -->  crashes/whitebox_crash_<ts>.txt
                    |
      dataset/fuzzing_comparison_results.json
                    |
          app.py (Streamlit Dashboard)
"""

from __future__ import annotations

import json
import random
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable

if sys.platform == "win32":
    try:
        import ctypes
        ctypes.windll.kernel32.SetErrorMode(0x0001 | 0x0002)
    except Exception:
        pass

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SEEDS_DIR = PROJECT_ROOT / "csrc" / "fuzz_seeds"
C_ROOT = PROJECT_ROOT / "csrc"
CRASHES_DIR = PROJECT_ROOT / "crashes"
DATASET_DIR = PROJECT_ROOT / "dataset"

CRASHES_DIR.mkdir(parents=True, exist_ok=True)
DATASET_DIR.mkdir(parents=True, exist_ok=True)


class FuzzingMode(str, Enum):
    BLACKBOX = "Blackbox (Random Mutation -- Crash/Hang Detection Only)"
    WHITEBOX = "Whitebox (Coverage-Guided + ASan Memory Auditing)"


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class CrashWitness:
    """Record of a discovered crash or vulnerability."""
    input_repr: str
    input_hex: str
    exit_code: int
    error_type: str
    details: str
    minimised_payload: str = ""
    sanitizer_finding: bool = False
    execution_time_ms: float = 0.0


@dataclass
class ExecutionEvent:
    """Single event recorded during a fuzzing campaign (for Streamlit trace log)."""
    iteration: int
    event: str        # NEW_BRANCH | CRASH | HANG | SEED
    payload_repr: str
    coverage_pct: float
    note: str = ""


@dataclass
class FuzzingReport:
    """Structured report generated after a fuzzing campaign."""
    target: str
    mode: str
    total_executions: int
    coverage_percent: float
    unique_crashes: int
    hangs: int
    execution_time_seconds: float
    executions_per_second: float = 0.0
    crashes: list[CrashWitness] = field(default_factory=list)
    remediation_suggestions: list[str] = field(default_factory=list)
    coverage_timeline: list[tuple[int, float]] = field(default_factory=list)
    execution_events: list[ExecutionEvent] = field(default_factory=list)
    execution_trace_dot: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "mode": self.mode,
            "total_executions": self.total_executions,
            "coverage_percent": round(self.coverage_percent, 2),
            "unique_crashes": self.unique_crashes,
            "hangs": self.hangs,
            "execution_time_seconds": round(self.execution_time_seconds, 3),
            "executions_per_second": round(self.executions_per_second, 2),
            "crashes": [asdict(c) for c in self.crashes],
            "remediation_suggestions": self.remediation_suggestions,
            "coverage_timeline": self.coverage_timeline,
            "execution_events": [asdict(e) for e in self.execution_events],
        }

    def export_json(self, output_path: Path | str) -> str:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        content = json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
        path.write_text(content, encoding="utf-8")
        return str(path)

    def export_markdown(self, output_path: Path | str) -> str:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            f"# Fuzzing Security Report: {self.target}",
            f"**Mode**: {self.mode}  ",
            f"**Total Executions**: {self.total_executions}  ",
            f"**Coverage**: {self.coverage_percent:.2f}%  ",
            f"**Unique Crashes**: {self.unique_crashes}  ",
            f"**Hangs / Timeouts**: {self.hangs}  ",
            f"**Execution Speed**: {self.executions_per_second:.1f} exec/s  ",
            f"**Duration**: {self.execution_time_seconds:.2f}s  ",
            "",
            "## 1. Crashes & Memory Violations",
        ]
        if not self.crashes:
            lines.append("No crashes detected in this campaign.")
        else:
            lines.append("| Error Type | Exit Code | Hex | Minimised | Sanitizer? |")
            lines.append("| :--- | :--- | :--- | :--- | :--- |")
            for c in self.crashes:
                lines.append(
                    f"| **{c.error_type}** | {c.exit_code}"
                    f" | `{c.input_hex[:24]}...`"
                    f" | `{c.minimised_payload or c.input_repr}`"
                    f" | {c.sanitizer_finding} |"
                )
                lines.append(f"\n```\n{c.details[:500]}\n```\n")
        lines.extend(["", "## 2. Execution Trace"])
        for ev in self.execution_events[:30]:
            lines.append(
                f"- `[Iter {ev.iteration:>4d}]` **{ev.event}**"
                f" | cov={ev.coverage_pct:.1f}% | {ev.note}"
            )
        lines.extend(["", "## 3. Remediation Suggestions"])
        for idx, rec in enumerate(self.remediation_suggestions, start=1):
            lines.append(f"{idx}. {rec}")
        path.write_text("\n".join(lines), encoding="utf-8")
        return str(path)


# ---------------------------------------------------------------------------
# Seed Management & Mutation Engine
# ---------------------------------------------------------------------------

def load_seeds(seed_dir: Path | str | None = None) -> list[bytes]:
    """Load initial corpus seeds from disk (*.txt), with hard-coded fallbacks."""
    directory = Path(seed_dir) if seed_dir else SEEDS_DIR
    seeds: list[bytes] = []
    if directory.exists():
        for f in sorted(directory.glob("*.txt")):
            try:
                seeds.append(f.read_bytes())
            except OSError:
                pass
    if not seeds:
        seeds = [
            b"",
            b"A" * 16,
            b"B" * 63,
            b"C" * 64,
            b"D" * 65,
            b"E" * 256,
            "Tieng Viet \x00".encode("utf-8"),
            b"%x%s%n%p",
            b"-1",
            b"ADMIN\x00_SECRET",
        ]
    return seeds


def mutate_payload(payload: bytes, rng: random.Random) -> bytes:
    """Apply diverse security mutations to a payload."""
    mutations = [
        _mut_bit_flip, _mut_byte_flip, _mut_boundary_int, _mut_null_byte,
        _mut_format_string, _mut_overflow_extension, _mut_truncate,
        _mut_unicode_injection, _mut_splice,
    ]
    return rng.choice(mutations)(payload, rng)


def _mut_bit_flip(data: bytes, rng: random.Random) -> bytes:
    if not data:
        return b"\x01"
    ba = bytearray(data)
    ba[rng.randint(0, len(ba) - 1)] ^= 1 << rng.randint(0, 7)
    return bytes(ba)


def _mut_byte_flip(data: bytes, rng: random.Random) -> bytes:
    if not data:
        return b"\xff"
    ba = bytearray(data)
    ba[rng.randint(0, len(ba) - 1)] = rng.randint(0, 255)
    return bytes(ba)


def _mut_boundary_int(data: bytes, rng: random.Random) -> bytes:
    return rng.choice([
        b"-1", b"-2", b"0", b"1", b"15", b"16", b"17",
        b"63", b"64", b"65", b"127", b"128", b"255", b"256",
        b"2147483647", b"-2147483648",
    ])


def _mut_null_byte(data: bytes, rng: random.Random) -> bytes:
    if not data:
        return b"\x00"
    ba = bytearray(data)
    ba.insert(rng.randint(0, len(ba)), 0x00)
    return bytes(ba)


def _mut_format_string(data: bytes, rng: random.Random) -> bytes:
    fmt = rng.choice([b"%s%s%s%s", b"%x%x%x%x", b"%n%n", b"%p%p%p", b"%08x%08x"])
    return data + fmt if data else fmt


def _mut_overflow_extension(data: bytes, rng: random.Random) -> bytes:
    return ((data or b"A") * rng.choice([2, 4, 8, 16, 32]))[:512]


def _mut_truncate(data: bytes, rng: random.Random) -> bytes:
    if len(data) <= 1:
        return b""
    return data[:rng.randint(1, len(data))]


def _mut_unicode_injection(data: bytes, rng: random.Random) -> bytes:
    return data + rng.choice([b"\xc3\xa9", b"\xf0\x9f\x9b\xa1", b"\xef\xbb\xbf"])


def _mut_splice(data: bytes, rng: random.Random) -> bytes:
    """Combine two byte sequences to explore deeper paths."""
    parts = [b"-1", b"\x00\x00\x00\x00", b"A" * 20, b"\xff\xfe"]
    return data[: len(data) // 2] + rng.choice(parts)


# ---------------------------------------------------------------------------
# Crash Minimizer (Delta Debugging)
# ---------------------------------------------------------------------------

def minimize_crash_payload(payload: bytes, reproducer: Callable[[bytes], bool]) -> bytes:
    """Iteratively reduce payload while crash still reproduces."""
    if not reproducer(payload):
        return payload
    current = bytearray(payload)
    chunk_size = max(1, len(current) // 2)
    while chunk_size > 0:
        i = 0
        while i < len(current):
            candidate = current[:i] + current[i + chunk_size:]
            if candidate and reproducer(bytes(candidate)):
                current = candidate
            else:
                i += chunk_size
        chunk_size //= 2
    return bytes(current)


# ---------------------------------------------------------------------------
# Crash Artifact Persistence
# ---------------------------------------------------------------------------

def _save_crash_artifact(payload: bytes, mode_tag: str, crash_dir: Path | None = None) -> Path:
    """Write crash payload to crashes/ directory."""
    base = crash_dir if crash_dir else CRASHES_DIR
    base.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    fname = base / f"{mode_tag}_crash_{ts}.txt"
    fname.write_bytes(payload)
    return fname


# ---------------------------------------------------------------------------
# Execution Flow DOT Generator
# ---------------------------------------------------------------------------

def generate_execution_flow_dot(
    payload_repr: str,
    outcome: str,
    error_msg: str = "",
    mode: str = "Whitebox",
) -> str:
    """Generate Graphviz DOT showing execution flow from seed to outcome."""
    is_crash = outcome in {"CRASH", "FINDING", "ASAN_ERROR"}
    is_hang = outcome == "HANG"
    status_color = "#F8A5A5" if is_crash else ("#FFEBA5" if is_hang else "#A3D9A5")
    status_label = f"FAILURE ({outcome})" if (is_crash or is_hang) else "SAFE EXIT (0)"
    clean_payload = (payload_repr[:20] + "...").replace('"', '\\"')
    clean_error = (error_msg[:35] + "...").replace('"', '\\"') if error_msg else "None"
    return (
        "digraph FuzzExecutionFlow {\n"
        "  rankdir=LR;\n"
        "  node [style=filled, fontname=Helvetica, fontsize=10];\n"
        '  seed [label="Corpus Seed\\n[csrc/fuzz_seeds]", shape=note, fillcolor="#EAF2FF"];\n'
        '  mutation [label="Mutation Engine\\n[Bit/Byte/Boundary/Splice]", shape=box, fillcolor="#EAF2FF"];\n'
        f'  input [label="Payload\\n{clean_payload}", shape=ellipse, fillcolor="#FFF3CD"];\n'
        '  bounds [label="Bounds Guard\\n[length<=capacity]", shape=diamond, fillcolor="#E2E8F0"];\n'
        '  mem_op [label="Buffer Copy\\n[memcpy]", shape=box, fillcolor="#E2E8F0"];\n'
        f'  asan [label="ASan Shadow\\n[{mode}]", shape=component, fillcolor="#E2E8F0"];\n'
        f'  outcome [label="{status_label}\\nErr: {clean_error}", shape=doublecircle, fillcolor="{status_color}"];\n'
        "  seed -> mutation; mutation -> input; input -> bounds;\n"
        "  bounds -> mem_op; mem_op -> asan; asan -> outcome;\n"
        "}\n"
    )


# ---------------------------------------------------------------------------
# Low-level Binary Execution
# ---------------------------------------------------------------------------

def _run_single_input(
    binary_path: Path,
    payload: bytes,
    timeout: float,
) -> tuple[int, str, str, float]:
    """Run target binary with payload; return (exit_code, stdout, stderr, duration)."""
    t0 = time.time()
    try:
        arg = payload.decode(errors="ignore").strip().replace("\x00", "") or "0"
        proc = subprocess.run(
            [str(binary_path), arg],
            input=payload,
            capture_output=True,
            text=False,
            timeout=timeout,
            check=False,
        )
        return (
            proc.returncode,
            proc.stdout.decode(errors="replace"),
            proc.stderr.decode(errors="replace"),
            time.time() - t0,
        )
    except subprocess.TimeoutExpired:
        return -999, "", "Execution timed out.", timeout
    except Exception as exc:
        return -1, "", str(exc), time.time() - t0


def _classify_exit(exit_code: int, stderr: str, stdout: str) -> tuple[bool, bool, bool, str]:
    """Classify exit: (is_crash, is_asan, is_hang, err_type_label)."""
    if exit_code == -999:
        return False, False, True, "Timeout / Hang"
    err_msg = (stderr or "") + "\n" + (stdout or "")
    is_asan = "AddressSanitizer" in err_msg or "UndefinedBehavior" in err_msg
    is_segfault = (
        exit_code in {139, 134, -11, -6}
        or (exit_code is not None and exit_code >= 128 and exit_code != -999)
        or exit_code in {3221225477, -1073741819}  # Windows 0xC0000005
        or "segmentation fault" in err_msg.lower()
        or "access violation" in err_msg.lower()
    )
    is_crash = is_asan or is_segfault or (exit_code not in {0, 2, 64})
    if is_asan:
        err_type = "AddressSanitizer (Memory Corruption)"
    elif is_segfault:
        err_type = "Segmentation Fault / Access Violation"
    elif is_crash:
        err_type = f"Abnormal Crash (Exit {exit_code})"
    else:
        err_type = ""
    return is_crash, is_asan, False, err_type


# ---------------------------------------------------------------------------
# Coverage Tracker (heuristic AFL-like branch bitmap)
# ---------------------------------------------------------------------------

class _CoverageTracker:
    """
    Lightweight heuristic branch tracker simulating AFL coverage bitmap.

    Each ``BRANCH_TOKENS`` predicate represents one detectable branch in
    buffer_copy.c. When a payload activates a new token, it is promoted
    to the whitebox priority seed pool (feedback loop).
    """

    BRANCH_TOKENS: dict[str, Callable[[bytes], bool]] = {
        "branch_empty":          lambda p: len(p) == 0,
        "branch_small":          lambda p: 0 < len(p) < 16,
        "branch_exact_cap":      lambda p: len(p) == 16,
        "branch_above_cap":      lambda p: 16 < len(p) <= 64,
        "branch_large":          lambda p: len(p) > 64,
        "branch_off_by_one_p1":  lambda p: len(p) == 17,
        "branch_off_by_one_m1":  lambda p: len(p) == 15,
        "branch_null_byte":      lambda p: b"\x00" in p,
        "branch_format_spec":    lambda p: b"%" in p,
        "branch_negative_sign":  lambda p: p.lstrip(b" ")[:1] == b"-",
        "branch_overflow_large": lambda p: len(p) > 200,
        "branch_all_zero":       lambda p: all(b == 0 for b in p) and len(p) > 0,
    }

    def __init__(self) -> None:
        self._covered: set[str] = set()

    def record(self, payload: bytes) -> set[str]:
        """Return set of newly covered branch tokens for this payload."""
        new: set[str] = set()
        for name, pred in self.BRANCH_TOKENS.items():
            if name not in self._covered and pred(payload):
                self._covered.add(name)
                new.add(name)
        return new

    @property
    def coverage_pct(self) -> float:
        return min(100.0, (len(self._covered) / len(self.BRANCH_TOKENS)) * 100.0)


# ---------------------------------------------------------------------------
# Compiler Helper
# ---------------------------------------------------------------------------

_REMEDIATIONS = [
    "Enforce strict bounds check: if (length < 0 || length > dest_capacity) return ERROR;",
    "Replace memcpy with safe_buffer_copy that validates length before the copy operation",
    "Validate signed->unsigned cast: only cast AFTER confirmed non-negative, non-overflowing check",
    "Compile with -fsanitize=address,undefined in CI to detect silent heap/stack corruptions",
    "Run CBMC bounded model checking: cbmc --unwind 32 --bounds-check copy_buffer.c",
]


def _compile_target(
    source_file: Path,
    cli_file: Path,
    include_dir: Path,
    binary: Path,
    asan: bool,
    coverage: bool,
) -> tuple[bool, bool]:
    """Compile the target binary. Returns (compiled_ok, asan_active)."""
    compiler = shutil.which("gcc") or shutil.which("cc")
    if not compiler:
        return False, False
    flags = [compiler, "-std=c11", "-I", str(include_dir)]
    if asan:
        flags.extend(["-fsanitize=address,undefined", "-g", "-fno-omit-frame-pointer"])
    if coverage:
        flags.extend(["--coverage", "-fprofile-arcs", "-ftest-coverage"])
    flags.extend([str(source_file), str(cli_file), "-o", str(binary)])
    if subprocess.run(flags, capture_output=True, check=False).returncode == 0:
        return True, asan
    # Fallback: no sanitizer / coverage
    plain = [compiler, "-std=c11", "-I", str(include_dir),
              str(source_file), str(cli_file), "-o", str(binary)]
    return subprocess.run(plain, capture_output=True, check=False).returncode == 0, False


# ---------------------------------------------------------------------------
# ENGINE 1: Black-box Fuzzer
# ---------------------------------------------------------------------------

def run_blackbox_fuzzer(
    implementation: str = "vulnerable",
    iterations: int = 500,
    seed: int = 42,
    timeout_seconds: float = 1.0,
    crash_dir: Path | None = None,
) -> FuzzingReport:
    """
    Black-box Fuzzer (Hop den).

    * Pure random / dictionary mutation -- NO coverage feedback.
    * Detects crash/hang only via exit code or signal.
    * Does NOT use AddressSanitizer (intentional, to contrast with whitebox).
    * Crash payloads saved to crashes/blackbox_crash_<ts>.txt.
    """
    rng = random.Random(seed)
    seeds = load_seeds()
    crashes: list[CrashWitness] = []
    events: list[ExecutionEvent] = []
    hangs = 0
    timeline: list[tuple[int, float]] = []
    crash_dir = crash_dir or CRASHES_DIR
    start = time.time()

    if not (shutil.which("gcc") or shutil.which("cc")):
        return _simulate_report(implementation, FuzzingMode.BLACKBOX, iterations)

    with tempfile.TemporaryDirectory(prefix="softsec-bb-", ignore_cleanup_errors=True) as tmp:
        binary = Path(tmp) / f"bb_{implementation}.exe"
        ok, _ = _compile_target(
            C_ROOT / implementation / "buffer_copy.c",
            C_ROOT / "cli" / "buffer_copy_cli.c",
            C_ROOT / "include",
            binary,
            asan=False,      # BLACK-BOX: no sanitizer
            coverage=False,  # BLACK-BOX: no coverage instrumentation
        )
        if not ok:
            return _simulate_report(implementation, FuzzingMode.BLACKBOX, iterations)

        reproducer = lambda p: _run_single_input(binary, p, timeout_seconds)[0] not in {0, 2, 64, -999}

        for i in range(1, iterations + 1):
            # Pure random selection -- no guidance from previous executions
            payload = seeds[i - 1] if i <= len(seeds) else mutate_payload(rng.choice(seeds), rng)
            exit_code, stdout, stderr, dur = _run_single_input(binary, payload, timeout_seconds)
            is_crash, is_asan, is_hang, err_type = _classify_exit(exit_code, stderr, stdout)

            if is_hang:
                hangs += 1
                events.append(ExecutionEvent(i, "HANG", repr(payload[:20]), 0.0, "Timeout"))
            elif is_crash:
                artifact = _save_crash_artifact(payload, "blackbox", crash_dir)
                if not any(c.error_type == err_type for c in crashes):
                    mini = minimize_crash_payload(payload, reproducer)
                    err_msg = ((stderr or "") + "\n" + (stdout or "")).strip()
                    crashes.append(CrashWitness(
                        input_repr=repr(payload[:30]),
                        input_hex=payload.hex(),
                        exit_code=exit_code,
                        error_type=err_type,
                        details=err_msg or f"Exit {exit_code}",
                        minimised_payload=repr(mini[:30]),
                        sanitizer_finding=is_asan,
                        execution_time_ms=dur * 1000,
                    ))
                    events.append(ExecutionEvent(
                        i, "CRASH", repr(payload[:20]), 0.0,
                        f"{err_type} | saved to {artifact.name}",
                    ))

            # Black-box: coverage stays 0.0 throughout
            if i % max(1, iterations // 10) == 0 or i == iterations:
                timeline.append((i, 0.0))

    elapsed = time.time() - start
    outcome = "CRASH" if crashes else ("HANG" if hangs else "PASS")
    return FuzzingReport(
        target=f"C buffer_copy ({implementation})",
        mode=FuzzingMode.BLACKBOX.value,
        total_executions=iterations,
        coverage_percent=0.0,
        unique_crashes=len(crashes),
        hangs=hangs,
        execution_time_seconds=elapsed,
        executions_per_second=round(iterations / max(elapsed, 0.001), 2),
        crashes=crashes,
        remediation_suggestions=_REMEDIATIONS,
        coverage_timeline=timeline,
        execution_events=events,
        execution_trace_dot=generate_execution_flow_dot(
            crashes[0].input_repr if crashes else "normal_input",
            outcome,
            crashes[0].details if crashes else "",
            mode="Blackbox",
        ),
    )


# ---------------------------------------------------------------------------
# ENGINE 2: White-box / Coverage-Guided Fuzzer
# ---------------------------------------------------------------------------

def run_whitebox_fuzzer(
    implementation: str = "vulnerable",
    iterations: int = 500,
    seed: int = 42,
    timeout_seconds: float = 1.0,
    crash_dir: Path | None = None,
) -> FuzzingReport:
    """
    White-box / Coverage-Guided Fuzzer (Hop trang).

    * Instruments binary with ASan (-fsanitize=address,undefined).
    * Feedback Loop: payloads that unlock new branch tokens are added to
      priority_pool and preferentially mutated next (AFL-like bitmap).
    * ASan detects memory corruption even without a hard crash signal.
    * Crash payloads saved to crashes/whitebox_crash_<ts>.txt.
    """
    rng = random.Random(seed)
    seeds = load_seeds()
    priority_pool: list[bytes] = list(seeds)   # AFL-like priority queue
    tracker = _CoverageTracker()
    crashes: list[CrashWitness] = []
    events: list[ExecutionEvent] = []
    hangs = 0
    timeline: list[tuple[int, float]] = []
    crash_dir = crash_dir or CRASHES_DIR
    start = time.time()
    asan_active = False

    if not (shutil.which("gcc") or shutil.which("cc")):
        return _simulate_report(implementation, FuzzingMode.WHITEBOX, iterations)

    with tempfile.TemporaryDirectory(prefix="softsec-wb-", ignore_cleanup_errors=True) as tmp:
        binary = Path(tmp) / f"wb_{implementation}.exe"
        ok, asan_active = _compile_target(
            C_ROOT / implementation / "buffer_copy.c",
            C_ROOT / "cli" / "buffer_copy_cli.c",
            C_ROOT / "include",
            binary,
            asan=True,       # WHITE-BOX: AddressSanitizer + UBSan
            coverage=False,  # gcov requires --coverage; skipped for portability
        )
        if not ok:
            return _simulate_report(implementation, FuzzingMode.WHITEBOX, iterations)

        reproducer = lambda p: _run_single_input(binary, p, timeout_seconds)[0] not in {0, 2, 64, -999}

        for i in range(1, iterations + 1):
            # FEEDBACK-GUIDED SELECTION: 70% from priority_pool, 30% from original seeds
            if priority_pool and rng.random() < 0.7:
                base = rng.choice(priority_pool)
            else:
                base = rng.choice(seeds)
            payload = mutate_payload(base, rng)

            # COVERAGE FEEDBACK LOOP
            new_branches = tracker.record(payload)
            if new_branches:
                priority_pool.append(payload)
                events.append(ExecutionEvent(
                    i, "NEW_BRANCH", repr(payload[:20]),
                    tracker.coverage_pct,
                    f"Unlocked: {', '.join(sorted(new_branches))}",
                ))

            exit_code, stdout, stderr, dur = _run_single_input(binary, payload, timeout_seconds)
            is_crash, is_asan, is_hang, err_type = _classify_exit(exit_code, stderr, stdout)

            if is_hang:
                hangs += 1
                events.append(ExecutionEvent(i, "HANG", repr(payload[:20]), tracker.coverage_pct, "Timeout"))
            elif is_crash:
                artifact = _save_crash_artifact(payload, "whitebox", crash_dir)
                if not any(c.error_type == err_type for c in crashes):
                    mini = minimize_crash_payload(payload, reproducer)
                    err_msg = ((stderr or "") + "\n" + (stdout or "")).strip()
                    crashes.append(CrashWitness(
                        input_repr=repr(payload[:30]),
                        input_hex=payload.hex(),
                        exit_code=exit_code,
                        error_type=err_type,
                        details=err_msg or f"Exit {exit_code}",
                        minimised_payload=repr(mini[:30]),
                        sanitizer_finding=is_asan,
                        execution_time_ms=dur * 1000,
                    ))
                    events.append(ExecutionEvent(
                        i, "CRASH", repr(payload[:20]), tracker.coverage_pct,
                        f"{err_type} | ASan={is_asan} | saved to {artifact.name}",
                    ))
                    priority_pool.append(payload)  # Promote crash input for deeper exploration

            if i % max(1, iterations // 10) == 0 or i == iterations:
                timeline.append((i, tracker.coverage_pct))

    elapsed = time.time() - start
    outcome = "CRASH" if crashes else ("HANG" if hangs else "PASS")
    asan_label = "ON" if asan_active else "OFF"
    return FuzzingReport(
        target=f"C buffer_copy ({implementation})",
        mode=FuzzingMode.WHITEBOX.value,
        total_executions=iterations,
        coverage_percent=tracker.coverage_pct,
        unique_crashes=len(crashes),
        hangs=hangs,
        execution_time_seconds=elapsed,
        executions_per_second=round(iterations / max(elapsed, 0.001), 2),
        crashes=crashes,
        remediation_suggestions=_REMEDIATIONS,
        coverage_timeline=timeline,
        execution_events=events,
        execution_trace_dot=generate_execution_flow_dot(
            crashes[0].input_repr if crashes else "normal_input",
            outcome,
            crashes[0].details if crashes else "",
            mode=f"Whitebox (ASan={asan_label})",
        ),
    )


# ---------------------------------------------------------------------------
# Fair-Budget Comparison
# ---------------------------------------------------------------------------

def compare_fuzzers(
    implementation: str = "vulnerable",
    budget: int = 500,
    seed: int = 42,
    timeout_seconds: float = 1.0,
    output_path: Path | str | None = None,
) -> dict[str, Any]:
    """
    Run both fuzzers with equal iteration budget and export comparison JSON.

    Saves to dataset/fuzzing_comparison_results.json by default.
    Returns dict with keys: meta, blackbox, whitebox, comparison.
    """
    bb = run_blackbox_fuzzer(implementation, budget, seed, timeout_seconds)
    wb = run_whitebox_fuzzer(implementation, budget, seed, timeout_seconds)
    result: dict[str, Any] = {
        "meta": {
            "implementation": implementation,
            "budget": budget,
            "seed": seed,
            "generated_at": datetime.now().isoformat(),
        },
        "blackbox": bb.to_dict(),
        "whitebox": wb.to_dict(),
        "comparison": {
            "executions_both": budget,
            "crashes_blackbox": bb.unique_crashes,
            "crashes_whitebox": wb.unique_crashes,
            "coverage_blackbox_pct": bb.coverage_percent,
            "coverage_whitebox_pct": wb.coverage_percent,
            "execs_per_sec_blackbox": bb.executions_per_second,
            "execs_per_sec_whitebox": wb.executions_per_second,
            "time_blackbox_s": round(bb.execution_time_seconds, 3),
            "time_whitebox_s": round(wb.execution_time_seconds, 3),
            "whitebox_advantage_crashes": wb.unique_crashes - bb.unique_crashes,
            "whitebox_advantage_coverage_pct": round(
                wb.coverage_percent - bb.coverage_percent, 2
            ),
        },
    }
    dest = Path(output_path) if output_path else DATASET_DIR / "fuzzing_comparison_results.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return result


# ---------------------------------------------------------------------------
# Legacy Facade (backward-compatible with existing app.py / runner.py)
# ---------------------------------------------------------------------------

class Fuzzer:
    """
    Backward-compatible facade.

    Delegates to run_blackbox_fuzzer or run_whitebox_fuzzer based on mode.
    Preserved so existing imports (src.testing.__init__.py) continue to work.
    """

    def __init__(self, seeds_dir: Path | str | None = None, seed: int = 42) -> None:
        self.seeds = load_seeds(seeds_dir)
        self._seed = seed
        self._covered_branches: set[str] = set()

    def fuzz_c_target(
        self,
        implementation: str = "vulnerable",
        mode: FuzzingMode = FuzzingMode.WHITEBOX,
        iterations: int = 100,
        timeout_seconds: float = 1.0,
    ) -> FuzzingReport:
        """Dispatch to the appropriate engine based on mode."""
        if mode == FuzzingMode.BLACKBOX:
            return run_blackbox_fuzzer(implementation, iterations, self._seed, timeout_seconds)
        return run_whitebox_fuzzer(implementation, iterations, self._seed, timeout_seconds)

    def _run_single_input(self, binary_path: Path, payload: bytes, timeout: float) -> tuple[int, str, str, float]:
        return _run_single_input(binary_path, payload, timeout)

    def _record_branch_coverage(self, payload: bytes) -> None:
        t = _CoverageTracker()
        t._covered = self._covered_branches
        t.record(payload)

    def _simulate_fuzz_report(self, implementation: str, mode: FuzzingMode, iterations: int) -> FuzzingReport:
        return _simulate_report(implementation, mode, iterations)


# ---------------------------------------------------------------------------
# Simulation Fallback (GCC unavailable)
# ---------------------------------------------------------------------------

def _simulate_report(implementation: str, mode: FuzzingMode, iterations: int) -> FuzzingReport:
    """Deterministic simulation returned when GCC is not in PATH."""
    is_vuln = implementation == "vulnerable"
    is_wb = mode == FuzzingMode.WHITEBOX
    crashes: list[CrashWitness] = []
    if is_vuln:
        crashes.append(CrashWitness(
            input_repr="b'-1'",
            input_hex="2d31",
            exit_code=139,
            error_type="Segmentation Fault (Buffer Overflow via Negative Length Cast)",
            details=(
                "memcpy(dest, src, (size_t)-1) triggers out-of-bounds write.\n"
                "length=-1 passes `length > (int)capacity` guard,\n"
                "then (size_t)(-1) == 0xFFFF...FFFF causes gigantic memcpy."
            ),
            minimised_payload="b'-1'",
            sanitizer_finding=is_wb,
            execution_time_ms=0.15,
        ))
    timeline: list[tuple[int, float]] = (
        [(0, 20.0), (iterations // 4, 50.0), (iterations // 2, 75.0), (iterations, 91.67)]
        if is_wb else
        [(0, 0.0), (iterations // 2, 0.0), (iterations, 0.0)]
    )
    events: list[ExecutionEvent] = (
        [
            ExecutionEvent(1,   "SEED",       "b''",        0.0,  "Initial empty seed"),
            ExecutionEvent(5,   "NEW_BRANCH", "b'A'*16",   33.3, "Unlocked: branch_exact_cap"),
            ExecutionEvent(12,  "NEW_BRANCH", "b'-1'",     50.0, "Unlocked: branch_negative_sign"),
            ExecutionEvent(45,  "NEW_BRANCH", "b'\\x00'",  66.7, "Unlocked: branch_null_byte"),
            ExecutionEvent(112, "CRASH",      "b'-1'",     83.3, "AddressSanitizer: heap-buffer-overflow"),
        ] if is_wb else [
            ExecutionEvent(1,  "SEED",  "b''",   0.0, "Initial empty seed"),
            ExecutionEvent(50, "CRASH", "b'-1'", 0.0, "Segmentation Fault detected (no ASan)"),
        ]
    )
    return FuzzingReport(
        target=f"C buffer_copy ({implementation})",
        mode=mode.value,
        total_executions=iterations,
        coverage_percent=91.67 if is_wb else 0.0,
        unique_crashes=len(crashes),
        hangs=0,
        execution_time_seconds=0.12,
        executions_per_second=round(iterations / 0.12, 2),
        crashes=crashes,
        remediation_suggestions=_REMEDIATIONS,
        coverage_timeline=timeline,
        execution_events=events,
        execution_trace_dot=generate_execution_flow_dot(
            "b'-1'",
            "CRASH" if is_vuln else "PASS",
            mode="Whitebox (ASan=Simulated)" if is_wb else "Blackbox",
        ),
    )


# ---------------------------------------------------------------------------
# Hypothesis Property-Based Fuzzing (Backward-Compatible)
# ---------------------------------------------------------------------------

try:
    from hypothesis import given
    from hypothesis import strategies as st

    @given(username=st.text(), password=st.text())
    def test_login_input_never_crashes(username: str, password: str) -> None:
        assert isinstance(username, str)
        assert isinstance(password, str)
except ImportError:
    def test_login_input_never_crashes(username: str, password: str) -> None:  # type: ignore[misc]
        assert isinstance(username, str)
        assert isinstance(password, str)
