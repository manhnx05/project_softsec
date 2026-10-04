import subprocess


def run_ruff(
    target: str = "src",
) -> dict:

    result = subprocess.run(
        [
            "ruff",
            "check",
            target,
        ],
        capture_output=True,
        text=True,
    )

    return {
        "tool": "ruff",
        "passed": result.returncode == 0,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def run_mypy(
    target: str = "src",
) -> dict:

    result = subprocess.run(
        [
            "mypy",
            target,
        ],
        capture_output=True,
        text=True,
    )

    return {
        "tool": "mypy",
        "passed": result.returncode == 0,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }