"""Deterministic mutation fuzzing for the LMS Python modules.

Each fuzz target generates random (but reproducible, given a seed) inputs and
asserts security invariants. A violated invariant is recorded as a finding so
the run exits with evidence instead of silently passing.
"""

from __future__ import annotations

import random
import string
from dataclasses import dataclass, field

from src.models.states import AuthState, EmailState
from src.modules.authentication import (
    AuthenticationModule,
    LoginParams,
)
from src.modules.email_notification import (
    EmailNotificationModule,
    EmailParams,
    MockEmailTransport,
)

USERNAME_ALPHABET = string.ascii_letters + string.digits + "._-"
PASSWORD_ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*"


@dataclass
class FuzzFinding:
    target: str
    input_repr: str
    violation: str


@dataclass
class FuzzReport:
    target: str
    iterations: int
    seed: int
    findings: list[FuzzFinding] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.findings


def _random_text(
    rng: random.Random,
    alphabet: str,
    minimum: int,
    maximum: int,
) -> str:
    length = rng.randint(minimum, maximum)
    return "".join(rng.choice(alphabet) for _ in range(length))


def _random_recipient(rng: random.Random) -> str:
    valid = rng.random() < 0.6
    local = _random_text(rng, string.ascii_lowercase + ".", 1, 10)
    if valid:
        return f"{local}@example.com"
    return rng.choice(
        ["", "not-an-email", local, f"{local}@", "@example.com", "a@b"]
    )


def fuzz_authentication(
    iterations: int,
    seed: int,
) -> FuzzReport:
    rng = random.Random(seed)
    report = FuzzReport(
        target="authentication",
        iterations=iterations,
        seed=seed,
    )

    for _ in range(iterations):
        username = _random_text(rng, USERNAME_ALPHABET, 1, 12)
        password = _random_text(rng, PASSWORD_ALPHABET, 8, 20)
        wrong = password + "x"

        auth = AuthenticationModule(
            LoginParams(
                max_attempts=3,
                session_ttl_seconds=3600,
                min_password_length=8,
            )
        )

        context = f"username={username!r}"

        try:
            user = auth.register(username, password)

            session = auth.login(username, password)
            if session is None or user.state != AuthState.LOGGED_IN:
                report.findings.append(
                    FuzzFinding(
                        "authentication",
                        context,
                        "correct login did not produce a logged-in session",
                    )
                )
                continue

            if auth.authenticate(session.token) is not user:
                report.findings.append(
                    FuzzFinding(
                        "authentication",
                        context,
                        "valid session token did not authenticate the user",
                    )
                )

            # Wrong password must never authenticate.
            wrong_session = auth.login(username, wrong)
            if wrong_session is not None:
                report.findings.append(
                    FuzzFinding(
                        "authentication",
                        context,
                        "wrong password produced a session",
                    )
                )

            # Drive the account to LOCKED and confirm it stays locked.
            for _ in range(3):
                auth.login(username, wrong)

            if user.failed_attempts > 3:
                report.findings.append(
                    FuzzFinding(
                        "authentication",
                        context,
                        "failed_attempts exceeded max_attempts",
                    )
                )

            if user.state != AuthState.LOCKED:
                report.findings.append(
                    FuzzFinding(
                        "authentication",
                        context,
                        "account did not lock after max failed attempts",
                    )
                )

            if auth.login(username, password) is not None:
                report.findings.append(
                    FuzzFinding(
                        "authentication",
                        context,
                        "locked account accepted a valid password",
                    )
                )

        except Exception as exc:  # noqa: BLE001 - fuzzing must catch everything
            report.findings.append(
                FuzzFinding(
                    "authentication",
                    context,
                    f"unexpected exception: {exc!r}",
                )
            )

    return report


def fuzz_email(iterations: int, seed: int) -> FuzzReport:
    rng = random.Random(seed)
    report = FuzzReport(target="email", iterations=iterations, seed=seed)

    for _ in range(iterations):
        recipient = _random_recipient(rng)
        valid = EmailNotificationModule.is_valid_email(recipient)
        module = EmailNotificationModule(EmailParams(max_retry=2))
        context = f"recipient={recipient!r}"

        try:
            if valid:
                notification = module.create(recipient, "Subject", "Body")
                if notification.state != EmailState.QUEUED:
                    report.findings.append(
                        FuzzFinding(
                            "email",
                            context,
                            "created notification is not QUEUED",
                        )
                    )
                    continue

                if not module.send(
                    notification.notification_id,
                    MockEmailTransport(should_fail=False),
                ):
                    report.findings.append(
                        FuzzFinding(
                            "email",
                            context,
                            "successful transport did not send",
                        )
                    )
                if notification.state != EmailState.SENT:
                    report.findings.append(
                        FuzzFinding(
                            "email",
                            context,
                            "notification not SENT after successful send",
                        )
                    )

                # Sending again is idempotent and never re-queues an SENT item.
                if not module.send(
                    notification.notification_id,
                    MockEmailTransport(should_fail=True),
                ):
                    report.findings.append(
                        FuzzFinding(
                            "email",
                            context,
                            "resending an SENT notification did not report success",
                        )
                    )
                if notification.state != EmailState.SENT:
                    report.findings.append(
                        FuzzFinding(
                            "email",
                            context,
                            "SENT notification changed state on resend",
                        )
                    )
            else:
                try:
                    module.create(recipient, "Subject", "Body")
                except ValueError:
                    continue
                report.findings.append(
                    FuzzFinding(
                        "email",
                        context,
                        "invalid recipient was accepted",
                    )
                )

        except Exception as exc:  # noqa: BLE001 - fuzzing must catch everything
            report.findings.append(
                FuzzFinding("email", context, f"unexpected exception: {exc!r}")
            )

    return report


def fuzz_email_retry(iterations: int, seed: int) -> FuzzReport:
    """Fuzz the retry counter and confirm ``retry_count <= max_retry``."""
    rng = random.Random(seed)
    report = FuzzReport(target="email_retry", iterations=iterations, seed=seed)

    for _ in range(iterations):
        max_retry = rng.randint(0, 5)
        module = EmailNotificationModule(EmailParams(max_retry=max_retry))
        context = f"max_retry={max_retry}"

        try:
            notification = module.create(
                "student@example.com", "Subject", "Body"
            )
            transport = MockEmailTransport(should_fail=True)
            attempts = rng.randint(1, max_retry + 4)

            for _ in range(attempts):
                module.send(notification.notification_id, transport)

            if notification.retry_count > max_retry:
                report.findings.append(
                    FuzzFinding(
                        "email_retry",
                        context,
                        "retry_count exceeded max_retry",
                    )
                )

            if (
                attempts > max_retry
                and notification.state != EmailState.FAILED
            ):
                report.findings.append(
                    FuzzFinding(
                        "email_retry",
                        context,
                        "retry budget was exhausted without entering FAILED",
                    )
                )

        except Exception as exc:  # noqa: BLE001 - fuzzing must catch everything
            report.findings.append(
                FuzzFinding(
                    "email_retry", context, f"unexpected exception: {exc!r}"
                )
            )

    return report


def run_fuzzing(
    iterations: int = 2000,
    seed: int = 0xC0FFEE,
) -> list[dict]:
    """Run every Python fuzz target and return UI-friendly results."""
    if iterations < 1:
        raise ValueError("iterations must be at least 1")

    reports = [
        fuzz_authentication(iterations, seed),
        fuzz_email(iterations, seed),
        fuzz_email_retry(iterations, seed),
    ]

    results = []
    for report in reports:
        results.append(
            {
                "name": f"Python fuzzing ({report.target})",
                "status": "PASS" if report.ok else "FINDING",
                "summary": (
                    f"{report.iterations} iterations with seed {report.seed}; "
                    f"{len(report.findings)} findings."
                ),
                "command": (
                    f"run_fuzzing(iterations={report.iterations}, "
                    f"seed={report.seed})"
                ),
                "details": "\n".join(
                    f"{finding.input_repr}: {finding.violation}"
                    for finding in report.findings
                ),
            }
        )

    return results
