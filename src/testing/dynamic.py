"""Dynamic testing: run the pytest suite through the active interpreter."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _run_pytest(arguments: list[str], timeout_seconds: int = 300) -> dict:
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "pytest", *arguments],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
    except FileNotFoundError as exc:
        return {
            "passed": False,
            "stdout": "",
            "stderr": str(exc),
        }
    except subprocess.TimeoutExpired:
        return {
            "passed": False,
            "stdout": "",
            "stderr": f"pytest timed out after {timeout_seconds}s.",
        }
    except OSError as exc:
        return {
            "passed": False,
            "stdout": "",
            "stderr": f"Could not start pytest: {exc}",
        }

    return {
        "passed": completed.returncode == 0,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def run_pytest(target: str = "tests") -> dict:
    result = _run_pytest([target, "-v"])
    return {"tool": "pytest", **result}


def run_coverage(target: str = "tests") -> dict:
    result = _run_pytest(
        [target, "--cov=src", "--cov-report=term-missing"]
    )
    return {"tool": "coverage", **result}


def run_dynamic_tests() -> list[dict]:
    """Run the pytest suite and return UI-friendly check results."""
    result = run_pytest("tests")
    return [
        {
            "name": "pytest test suite",
            "status": "PASS" if result["passed"] else "FINDING",
            "summary": (
                "All tests passed."
                if result["passed"]
                else result["stderr"] or "One or more tests failed."
            ),
            "command": "python -m pytest tests -v",
            "details": result["stdout"],
        }
    ]
