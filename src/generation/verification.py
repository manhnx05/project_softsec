"""Verify the artifacts produced by :class:`CodeGenerator`.

Three independent checks are exposed:

* :func:`verify_state_enums` imports every generated enum module and compares
  its members with the specification it was rendered from.
* :func:`verify_safe_c` compiles the generated safe C sources with a strict
  warning set and runs the CLI boundary cases against the produced binary.
* :func:`run_generated_pytest` writes a temporary pytest module for the
  generated enums and executes it through the active interpreter.

Every check returns a UI-friendly ``dict`` with ``name``, ``status``,
``summary``, ``command`` and ``details`` keys, using the same ``PASS``,
``FINDING``, ``UNAVAILABLE`` and ``ERROR`` vocabulary as the C analysis report.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

from src.c_analysis.model import BUFFER_CAPACITY
from src.generation.generator import (
    PROJECT_ROOT,
    state_enum_class_name,
    state_enum_file_name,
    verify_generated_module,
)
from src.specification.schemas import FunctionSpec

GENERATED_DIR = Path("generated")
C_CLI_SOURCE = PROJECT_ROOT / "csrc" / "cli" / "buffer_copy_cli.c"
C_SOURCES = ("buffer_copy.c", "buffer_copy.h")
C_CLI_CASES: tuple[tuple[str, int], ...] = (
    ("0", 0),
    ("1", 0),
    ("15", 0),
    (str(BUFFER_CAPACITY), 0),
    ("-1", 2),
    (str(BUFFER_CAPACITY + 1), 2),
    ("-2147483648", 2),
    ("2147483647", 2),
    ("not-an-integer", 64),
)


def _result(
    name: str,
    status: str,
    summary: str,
    command: str = "",
    details: str = "",
) -> dict[str, str]:
    return {
        "name": name,
        "status": status,
        "summary": summary,
        "command": command,
        "details": details,
    }


def _run(
    command: list[str],
    timeout_seconds: int,
) -> tuple[int | None, str, str | None]:
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
        return None, "", str(exc)
    except subprocess.TimeoutExpired:
        return None, "", f"Command timed out after {timeout_seconds}s."
    except OSError as exc:
        return None, "", f"Could not start command: {exc}"

    output = "\n".join(
        part for part in (completed.stdout, completed.stderr) if part
    ).strip()
    return completed.returncode, output, None


def verify_state_enums(
    functions: Sequence[FunctionSpec],
    generated_dir: str | Path = GENERATED_DIR,
) -> list[dict[str, str]]:
    """Import each generated enum module and compare members with the spec."""
    directory = Path(generated_dir)
    results: list[dict[str, str]] = []

    for function in functions:
        class_name = state_enum_class_name(function.name)
        expected_states = [state.name for state in function.states]
        path = directory / state_enum_file_name(function.name)
        name = f"Generated enum {class_name}"
        command = f"import {path} and compare {class_name} members"

        if not path.exists():
            results.append(
                _result(
                    name,
                    "ERROR",
                    f"Generated module not found: {path}. Generate the state "
                    "enums before testing them.",
                    command,
                )
            )
            continue

        errors = verify_generated_module(path, {class_name: expected_states})
        results.append(
            _result(
                name,
                "FINDING" if errors else "PASS",
                (
                    "Generated module does not match the specification."
                    if errors
                    else f"{class_name} exposes exactly the specified states."
                ),
                command,
                "\n".join(errors)
                or f"{class_name} = {', '.join(expected_states)}",
            )
        )

    return results


def verify_safe_c(
    generated_dir: str | Path = GENERATED_DIR,
    compiler: str = "gcc",
) -> dict[str, str]:
    """Compile the generated safe C files and exercise the CLI boundaries."""
    name = "Generated safe C compile and run"
    directory = Path(generated_dir)
    source = directory / "buffer_copy.c"
    header = directory / "buffer_copy.h"

    missing = [str(path) for path in (source, header) if not path.exists()]
    if missing:
        return _result(
            name,
            "ERROR",
            "Generated C artifacts are missing: "
            + ", ".join(missing)
            + ". Generate the safe C code before testing it.",
        )

    compiler_path = shutil.which(compiler)
    if compiler_path is None:
        return _result(
            name,
            "UNAVAILABLE",
            f"C compiler '{compiler}' was not found on PATH.",
        )

    with tempfile.TemporaryDirectory(prefix="lms-generated-c-") as temporary_dir:
        binary = Path(temporary_dir) / "generated_safe_copy"
        build_command = [
            compiler_path,
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(directory),
            str(source),
            str(C_CLI_SOURCE),
            "-o",
            str(binary),
        ]
        return_code, output, error = _run(build_command, timeout_seconds=60)
        rendered_command = " ".join(build_command)

        if error or return_code != 0:
            return _result(
                name,
                "ERROR",
                error or f"Generated C build failed with exit code {return_code}.",
                rendered_command,
                output,
            )

        failures: list[str] = []
        details: list[str] = []
        for input_value, expected_exit in C_CLI_CASES:
            run_code, run_output, run_error = _run(
                [str(binary), input_value],
                timeout_seconds=10,
            )
            matched = run_error is None and run_code == expected_exit
            if not matched:
                failures.append(f"length={input_value}")
            details.append(
                f"input={input_value!r}, expected_exit={expected_exit}, "
                f"actual_exit={run_code}, error={run_error or 'none'}\n{run_output}"
            )

    return _result(
        name,
        "FINDING" if failures else "PASS",
        (
            "Generated C binary deviated on: " + ", ".join(failures)
            if failures
            else f"Generated C binary compiled cleanly and matched all "
            f"{len(C_CLI_CASES)} boundary cases (capacity {BUFFER_CAPACITY})."
        ),
        rendered_command,
        "\n".join(details),
    )


def _render_test_module(
    functions: Sequence[FunctionSpec],
    generated_dir: Path,
) -> str:
    lines = [
        '"""Auto-generated pytest checks for the generated state enums."""',
        "",
        "import importlib.util",
        "from pathlib import Path",
        "",
        f"GENERATED_DIR = Path({str(generated_dir)!r})",
        "",
        "",
        "def _load(module_name: str, file_name: str):",
        "    spec = importlib.util.spec_from_file_location(",
        "        module_name, GENERATED_DIR / file_name",
        "    )",
        "    assert spec is not None and spec.loader is not None",
        "    module = importlib.util.module_from_spec(spec)",
        "    spec.loader.exec_module(module)",
        "    return module",
    ]

    for function in functions:
        class_name = state_enum_class_name(function.name)
        file_name = state_enum_file_name(function.name)
        states = [state.name for state in function.states]
        lines.extend(
            [
                "",
                "",
                f"def test_{file_name.removesuffix('.py')}_matches_spec():",
                f"    module = _load('generated_{file_name}', {file_name!r})",
                f"    members = [m.name for m in module.{class_name}]",
                f"    assert members == {states!r}",
            ]
        )

    return "\n".join(lines) + "\n"


def run_generated_pytest(
    functions: Sequence[FunctionSpec],
    generated_dir: str | Path = GENERATED_DIR,
) -> dict[str, str]:
    """Run a temporary pytest module against the generated enum files."""
    name = "pytest on generated enums"
    directory = Path(generated_dir).resolve()
    missing = [
        str(directory / state_enum_file_name(function.name))
        for function in functions
        if not (directory / state_enum_file_name(function.name)).exists()
    ]
    if not functions or missing:
        return _result(
            name,
            "ERROR",
            "Generated enum modules are missing: "
            + (", ".join(missing) if missing else "none")
            + ". Generate the state enums before testing them.",
        )

    source = _render_test_module(functions, directory)
    with tempfile.TemporaryDirectory(prefix="lms-generated-tests-") as temporary_dir:
        test_file = Path(temporary_dir) / "test_generated_states.py"
        test_file.write_text(source, encoding="utf-8")

        command = [
            sys.executable,
            "-m",
            "pytest",
            str(test_file),
            "-v",
            "-p",
            "no:cacheprovider",
        ]
        return_code, output, error = _run(command, timeout_seconds=180)

    passed = error is None and return_code == 0
    return _result(
        name,
        "PASS" if passed else "FINDING",
        (
            f"pytest validated {len(functions)} generated enum module(s)."
            if passed
            else error or f"pytest exited with code {return_code}."
        ),
        " ".join(command),
        output,
    )
