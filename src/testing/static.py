"""Static testing: linting, type checking, Z3 constraints, and BMC.

All external tools are invoked through the running interpreter
(``sys.executable -m <tool>``) so the virtual environment is always used
instead of whatever happens to be on ``PATH``.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from src.constraints.z3_solver import (
    Z3ConstraintEngine,
    check_locked_login_safety,
)
from src.verification.bmc import check_reachability
from src.verification.kripke import (
    build_auth_kripke,
    build_email_kripke,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _run_module(
    module: str,
    arguments: list[str],
    timeout_seconds: int = 120,
) -> tuple[int | None, str, str | None]:
    try:
        completed = subprocess.run(
            [sys.executable, "-m", module, *arguments],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
    except FileNotFoundError as exc:
        return None, "", str(exc)
    except subprocess.TimeoutExpired:
        return None, "", f"{module} timed out after {timeout_seconds}s."
    except OSError as exc:
        return None, "", f"Could not start {module}: {exc}"

    output = "\n".join(
        part for part in (completed.stdout, completed.stderr) if part
    ).strip()
    return completed.returncode, output, None


def run_ruff(target: str = "src") -> dict:
    return_code, output, error = _run_module("ruff", ["check", target])
    return {
        "tool": "ruff",
        "passed": return_code == 0,
        "command": f"{sys.executable} -m ruff check {target}",
        "stdout": output,
        "stderr": error or "",
    }


def run_mypy(target: str = "src") -> dict:
    return_code, output, error = _run_module("mypy", [target])
    return {
        "tool": "mypy",
        "passed": return_code == 0,
        "command": f"{sys.executable} -m mypy {target}",
        "stdout": output,
        "stderr": error or "",
    }


def run_z3_verification() -> list[dict]:
    """Run Z3 SAT/UNSAT checks for the modeled authentication policy."""
    engine = Z3ConstraintEngine()
    engine.add_authentication_constraints(
        max_attempts=3,
        min_password_length=8,
    )
    constraint_status = engine.status()

    safety_status = check_locked_login_safety()

    return [
        {
            "name": "Z3 authentication constraints",
            "status": "PASS" if constraint_status == "SAT" else "FINDING",
            "summary": (
                f"Constraint set is {constraint_status}."
                if constraint_status == "SAT"
                else f"Constraint set is {constraint_status}; expected SAT."
            ),
            "command": (
                "Z3ConstraintEngine.add_authentication_constraints"
                "(max_attempts=3, min_password_length=8)"
            ),
            "details": (
                "attempts >= 0 AND attempts <= max_attempts; "
                "password_length >= min_password_length; "
                "locked -> not login_allowed"
            ),
        },
        {
            "name": "Z3 locked-login safety",
            "status": "PASS" if safety_status == "UNSAT" else "FINDING",
            "summary": (
                "UNSAT: no model lets a locked account login."
                if safety_status == "UNSAT"
                else f"{safety_status}: the locked-login policy can be violated."
            ),
            "command": "check_locked_login_safety()",
            "details": (
                "Query: exists attempts/password_length such that "
                "locked AND login_allowed. UNSAT proves the policy holds."
            ),
        },
    ]


def _bmc_case(
    name: str,
    model,
    start: str,
    target: str,
    expected: str,
    bound: int,
) -> dict:
    result = check_reachability(model, start, target, bound=bound)
    passed = result.status == expected
    return {
        "name": name,
        "status": "PASS" if passed else "FINDING",
        "summary": (
            f"{result.status} for reachability '{start}' -> '{target}' "
            f"(expected {expected}, bound={bound})."
        ),
        "command": (
            f"check_reachability({name!r}, {start!r}, {target!r}, "
            f"bound={bound})"
        ),
        "details": result.detail,
    }


def run_bounded_model_checking() -> list[dict]:
    """Run Z3-based bounded model checking over the Kripke structures."""
    auth = build_auth_kripke()
    email = build_email_kripke()

    return [
        _bmc_case(
            "BMC auth: LOCKED reachable",
            auth,
            "LOGGED_OUT",
            "LOCKED",
            expected="SAT",
            bound=4,
        ),
        _bmc_case(
            "BMC auth: LOGGED_IN reachable",
            auth,
            "LOGGED_OUT",
            "LOGGED_IN",
            expected="SAT",
            bound=3,
        ),
        _bmc_case(
            "BMC email: SENT reachable",
            email,
            "IDLE",
            "SENT",
            expected="SAT",
            bound=4,
        ),
        _bmc_case(
            "BMC email: SENT is terminal",
            email,
            "SENT",
            "QUEUED",
            expected="UNSAT",
            bound=4,
        ),
    ]


def run_static_analysis() -> list[dict]:
    """Full static analysis: linters, Z3 constraints, and BMC."""
    results: list[dict] = []

    ruff = run_ruff("src")
    results.append(
        {
            "name": "ruff",
            "status": (
                "PASS"
                if ruff["passed"]
                else "UNAVAILABLE"
                if ruff["stderr"]
                else "FINDING"
            ),
            "summary": (
                "ruff reported no issues."
                if ruff["passed"]
                else ruff["stderr"] or "ruff reported issues."
            ),
            "command": "python -m ruff check src",
            "details": ruff["stdout"],
        }
    )

    mypy = run_mypy("src")
    results.append(
        {
            "name": "mypy",
            "status": (
                "PASS"
                if mypy["passed"]
                else "UNAVAILABLE"
                if mypy["stderr"]
                else "FINDING"
            ),
            "summary": (
                "mypy reported no issues."
                if mypy["passed"]
                else mypy["stderr"] or "mypy reported issues."
            ),
            "command": "python -m mypy src",
            "details": mypy["stdout"],
        }
    )

    results.extend(run_z3_verification())
    results.extend(run_bounded_model_checking())

    return results
