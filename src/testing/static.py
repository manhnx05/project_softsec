import subprocess
import sys


def _run_tool(tool: str, target: str) -> dict[str, object]:
    command = [sys.executable, "-m", tool]
    if tool == "ruff":
        command.extend(("check", target))
    else:
        command.append(target)

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )

    return {
        "tool": tool,
        "passed": result.returncode == 0,
        "exit_code": result.returncode,
        "command": " ".join(command),
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def run_ruff(
    target: str = "src",
) -> dict[str, object]:
    return _run_tool("ruff", target)


def run_mypy(
    target: str = "src",
) -> dict[str, object]:
    return _run_tool("mypy", target)