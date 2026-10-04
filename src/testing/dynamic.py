import subprocess


def run_pytest(
    target: str = "tests",
) -> dict:

    result = subprocess.run(
        [
            "pytest",
            target,
            "-v",
        ],
        capture_output=True,
        text=True,
    )

    return {
        "tool": "pytest",
        "passed": result.returncode == 0,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def run_coverage(
    target: str = "tests",
) -> dict:

    result = subprocess.run(
        [
            "pytest",
            target,
            "--cov=src",
            "--cov-report=term-missing",
        ],
        capture_output=True,
        text=True,
    )

    return {
        "tool": "coverage",
        "passed": result.returncode == 0,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }