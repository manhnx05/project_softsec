from dataclasses import dataclass
from typing import Callable

from src.models.states import AuthState


@dataclass
class Constraint:
    """
    Một ràng buộc của hệ thống.
    """

    name: str

    description: str

    check: Callable[[dict], bool]


# =============================================================
# AUTHENTICATION CONSTRAINTS
# =============================================================

AUTH_CONSTRAINTS = [

    Constraint(
        name="password_min_length",

        description=(
            "Password phải đạt độ dài tối thiểu."
        ),

        check=lambda ctx:
            len(ctx["password"])
            >= ctx["min_password_length"]
    ),

    Constraint(
        name="locked_cannot_login",

        description=(
            "Account LOCKED không được login."
        ),

        check=lambda ctx:
            not (
                ctx["state"]
                == AuthState.LOCKED

                and ctx["login_allowed"]
            )
    ),

    Constraint(
        name="max_failed_attempts",

        description=(
            "Số lần sai password "
            "không vượt max_attempts."
        ),

        check=lambda ctx:
            ctx["failed_attempts"]
            <= ctx["max_attempts"]
    ),

    Constraint(
        name="session_requires_login",

        description=(
            "Session hợp lệ yêu cầu "
            "user LOGGED_IN."
        ),

        check=lambda ctx:
            not ctx["session_valid"]

            or ctx["state"]
            == AuthState.LOGGED_IN
    )
]


# =============================================================
# EMAIL CONSTRAINTS
# =============================================================

EMAIL_CONSTRAINTS = [

    Constraint(
        name="valid_recipient",

        description=(
            "Recipient phải là email hợp lệ."
        ),

        check=lambda ctx:
            ctx["valid_recipient"]
    ),

    Constraint(
        name="queued_before_sent",

        description=(
            "Notification phải QUEUED "
            "trước khi SENT."
        ),

        check=lambda ctx:
            not ctx["sent"]
            or ctx["was_queued"]
    ),

    Constraint(
        name="retry_non_negative",

        description=(
            "Retry count không được âm."
        ),

        check=lambda ctx:
            ctx["retry_count"] >= 0
    ),

    Constraint(
        name="retry_limit",

        description=(
            "Retry count không vượt max_retry."
        ),

        check=lambda ctx:
            ctx["retry_count"]
            <= ctx["max_retry"]
    )
]


# =============================================================
# VERIFY
# =============================================================

def verify_constraints(
    constraints: list[Constraint],
    context: dict
) -> tuple[bool, list[str]]:

    errors = []

    for constraint in constraints:

        try:

            result = constraint.check(
                context
            )

        except Exception as exc:

            errors.append(
                f"{constraint.name}: "
                f"exception={exc}"
            )

            continue

        if not result:

            errors.append(
                f"{constraint.name}: "
                f"{constraint.description}"
            )

    return (
        len(errors) == 0,
        errors
    )