import subprocess
import sys


def run_pytest(
    target: str = "tests",
) -> dict[str, object]:

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            target,
            "-v",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    return {
        "tool": "pytest",
        "passed": result.returncode == 0,
        "exit_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def run_coverage(
    target: str = "tests",
) -> dict[str, object]:

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            target,
            "--cov=src",
            "--cov-report=term-missing",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    return {
        "tool": "coverage",
        "passed": result.returncode == 0,
        "exit_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }