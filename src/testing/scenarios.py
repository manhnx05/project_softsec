"""Declarative end-to-end test scenarios for the LMS security simulator.

Each scenario is declared once with its steps and expected outcome, then
executed by :func:`run_e2e_scenarios`. The same catalogue backs
``tests/test_e2e_scenarios.py`` and the "E2E Scenarios" tab of the dashboard,
so the documented list and the executed checks cannot drift apart.
"""

from __future__ import annotations

import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.c_analysis.model import find_bounded_counterexample
from src.constraints.z3_solver import check_locked_login_safety
from src.generation.generator import (
    CodeGenerator,
    state_enum_class_name,
    verify_generated_module,
)
from src.kripke.builder import build_kripke
from src.kripke.model import KripkeModel
from src.models.states import AuthState, EmailState
from src.modules.authentication import (
    AuthenticationModule,
    LoginParams,
    hash_password,
    verify_password,
)
from src.modules.email_notification import (
    EmailNotificationModule,
    EmailParams,
    MockEmailTransport,
)
from src.specification.loader import load_project_spec
from src.specification.schemas import FunctionSpec
from src.verification.bmc import check_reachability
from src.verification.constraints import (
    AUTH_CONSTRAINTS,
    EMAIL_CONSTRAINTS,
    verify_constraints,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SPECS_DIR = PROJECT_ROOT / "specs"
ANALYSIS_LENGTHS = range(-32, 33)

ScenarioCheck = Callable[[], tuple[bool, str]]


@dataclass(frozen=True)
class Scenario:
    """A single end-to-end LMS scenario."""

    id: str
    function: str
    title: str
    steps: tuple[str, ...]
    expected: str
    check: ScenarioCheck


def _functions() -> dict[str, FunctionSpec]:
    return {
        function.name: function
        for spec in load_project_spec(SPECS_DIR)
        for function in spec.functions
    }


def _reachable_states(model: KripkeModel) -> set[str]:
    if model.initial_state is None:
        return set()

    seen = {model.initial_state}
    pending = [model.initial_state]
    while pending:
        current = pending.pop()
        for successor in model.successors(current):
            if successor not in seen:
                seen.add(successor)
                pending.append(successor)
    return seen


def _locked_module() -> tuple[AuthenticationModule, str]:
    auth = AuthenticationModule(LoginParams(max_attempts=3))
    auth.register("lock-user", "SecurePass123")
    for _ in range(3):
        auth.login("lock-user", "WrongPass123")
    return auth, "lock-user"


# =============================================================
# AUTHENTICATION SCENARIOS
# =============================================================

def _auth_valid_login() -> tuple[bool, str]:
    auth = AuthenticationModule()
    user = auth.register("scenario-user", "SecurePass123")
    session = auth.login("scenario-user", "SecurePass123")
    authenticated = session is not None and auth.authenticate(session.token) is user
    return (
        user.state == AuthState.LOGGED_IN and authenticated,
        (
            f"state={user.state.value}, session_issued={session is not None}, "
            f"authenticate={authenticated}"
        ),
    )


def _auth_wrong_password() -> tuple[bool, str]:
    auth = AuthenticationModule()
    user = auth.register("scenario-user", "SecurePass123")
    session = auth.login("scenario-user", "WrongPass123")
    return (
        session is None
        and user.state == AuthState.LOGIN_FAILED
        and user.failed_attempts == 1,
        (
            f"session={session}, state={user.state.value}, "
            f"failed_attempts={user.failed_attempts}"
        ),
    )


def _auth_lockout_after_max_attempts() -> tuple[bool, str]:
    auth, username = _locked_module()
    user = auth.users[username]
    return (
        user.state == AuthState.LOCKED and user.failed_attempts == 3,
        f"state={user.state.value}, failed_attempts={user.failed_attempts}",
    )


def _auth_locked_rejects_correct_password() -> tuple[bool, str]:
    auth, username = _locked_module()
    session = auth.login(username, "SecurePass123")
    return (
        session is None and auth.users[username].state == AuthState.LOCKED,
        f"session={session}, state={auth.users[username].state.value}",
    )


def _auth_logout_invalidates_session() -> tuple[bool, str]:
    auth = AuthenticationModule()
    auth.register("scenario-user", "SecurePass123")
    session = auth.login("scenario-user", "SecurePass123")
    if session is None:
        return False, "login did not issue a session"

    logged_out = auth.logout(session.token)
    still_valid = auth.authenticate(session.token) is not None
    return (
        logged_out and not still_valid,
        f"logout={logged_out}, token_still_valid={still_valid}",
    )


def _auth_logout_revokes_all_sessions() -> tuple[bool, str]:
    auth = AuthenticationModule()
    auth.register("scenario-user", "SecurePass123")
    first = auth.login("scenario-user", "SecurePass123")
    second = auth.login("scenario-user", "SecurePass123")
    if first is None or second is None:
        return False, "login did not issue both sessions"

    auth.logout(first.token)
    second_valid = auth.authenticate(second.token) is not None
    new_session = auth.login("scenario-user", "SecurePass123")
    second_after_relogin = auth.authenticate(second.token) is not None
    return (
        not second_valid and not second_after_relogin and new_session is not None,
        (
            f"other_session_valid_after_logout={second_valid}, "
            f"other_session_valid_after_relogin={second_after_relogin}"
        ),
    )


def _auth_short_password_rejected() -> tuple[bool, str]:
    auth = AuthenticationModule(LoginParams(min_password_length=8))
    try:
        auth.register("short-user", "short")
    except ValueError as exc:
        return True, f"register rejected the password: {exc}"
    return False, "register accepted a password shorter than min_password_length"


def _auth_duplicate_username_rejected() -> tuple[bool, str]:
    auth = AuthenticationModule()
    auth.register("scenario-user", "SecurePass123")
    try:
        auth.register("scenario-user", "SecurePass123")
    except ValueError as exc:
        return True, f"duplicate registration rejected: {exc}"
    return False, "duplicate username was accepted"


def _auth_unknown_user_rejected() -> tuple[bool, str]:
    auth = AuthenticationModule()
    session = auth.login("missing-user", "SecurePass123")
    return (
        session is None and not auth.sessions,
        f"session={session}, active_sessions={len(auth.sessions)}",
    )


def _auth_expired_session_rejected() -> tuple[bool, str]:
    auth = AuthenticationModule(LoginParams(session_ttl_seconds=0))
    auth.register("scenario-user", "SecurePass123")
    session = auth.login("scenario-user", "SecurePass123")
    if session is None:
        return False, "login did not issue a session"
    return (
        auth.authenticate(session.token) is None,
        "session with ttl=0 was rejected by authenticate",
    )


def _auth_reset_lock_restores_access() -> tuple[bool, str]:
    auth, username = _locked_module()
    restored = auth.reset_lock(username)
    session = auth.login(username, "SecurePass123")
    return (
        restored
        and session is not None
        and auth.users[username].state == AuthState.LOGGED_IN,
        (
            f"reset_lock={restored}, state={auth.users[username].state.value}, "
            f"session={session is not None}"
        ),
    )


def _auth_password_hashes_are_salted() -> tuple[bool, str]:
    first = hash_password("SecurePass123")
    second = hash_password("SecurePass123")
    return (
        first != second
        and verify_password("SecurePass123", first)
        and verify_password("SecurePass123", second),
        f"hashes_differ={first != second}, both_verify=True",
    )


def _auth_weak_hash_parameters_rejected() -> tuple[bool, str]:
    algorithm, _, salt, digest = hash_password("SecurePass123").split("$")
    tampered = f"{algorithm}$1${salt}${digest}"
    return (
        verify_password("SecurePass123", tampered) is False,
        "hash with 1 PBKDF2 iteration was rejected",
    )


def _auth_constraints_hold_after_login() -> tuple[bool, str]:
    auth = AuthenticationModule()
    auth.register("scenario-user", "SecurePass123")
    user = auth.login("scenario-user", "SecurePass123") is not None
    passed, errors = verify_constraints(
        AUTH_CONSTRAINTS,
        {
            "password": "SecurePass123",
            "min_password_length": 8,
            "state": AuthState.LOGGED_IN,
            "login_allowed": True,
            "failed_attempts": 0,
            "max_attempts": 3,
            "session_valid": user,
        },
    )
    return passed, f"violations={errors or 'none'}"


def _auth_constraints_detect_locked_login() -> tuple[bool, str]:
    passed, errors = verify_constraints(
        AUTH_CONSTRAINTS,
        {
            "password": "SecurePass123",
            "min_password_length": 8,
            "state": AuthState.LOCKED,
            "login_allowed": True,
            "failed_attempts": 3,
            "max_attempts": 3,
            "session_valid": False,
        },
    )
    detected = not passed and any("locked_cannot_login" in error for error in errors)
    return detected, f"detected={detected}, violations={errors}"


# =============================================================
# EMAIL NOTIFICATION SCENARIOS
# =============================================================

def _email_successful_delivery() -> tuple[bool, str]:
    module = EmailNotificationModule()
    notification = module.create("student@example.com", "Subject", "Body")
    queued = notification.state == EmailState.QUEUED
    sent = module.send(notification.notification_id, MockEmailTransport())
    return (
        queued and sent and notification.state == EmailState.SENT,
        f"queued={queued}, send={sent}, state={notification.state.value}",
    )


def _email_invalid_recipient_rejected() -> tuple[bool, str]:
    module = EmailNotificationModule()
    try:
        module.create("not-an-email", "Subject", "Body")
    except ValueError as exc:
        return True, f"create rejected the recipient: {exc}"
    return False, "an invalid recipient was accepted"


def _email_transient_failure_then_retry() -> tuple[bool, str]:
    module = EmailNotificationModule()
    notification = module.create("student@example.com", "Subject", "Body")
    failed = module.send(
        notification.notification_id,
        MockEmailTransport(should_fail=True),
    )
    recovered = module.send(
        notification.notification_id,
        MockEmailTransport(),
    )
    return (
        not failed
        and recovered
        and notification.retry_count == 1
        and notification.state == EmailState.SENT,
        (
            f"failed={failed}, recovered={recovered}, "
            f"retry_count={notification.retry_count}, state={notification.state.value}"
        ),
    )


def _email_retry_limit_exceeded() -> tuple[bool, str]:
    module = EmailNotificationModule(EmailParams(max_retry=2))
    notification = module.create("student@example.com", "Subject", "Body")
    transport = MockEmailTransport(should_fail=True)
    for _ in range(3):
        module.send(notification.notification_id, transport)
    return (
        notification.retry_count == 2 and notification.state == EmailState.FAILED,
        (
            f"retry_count={notification.retry_count}, "
            f"state={notification.state.value}"
        ),
    )


def _email_unknown_notification_rejected() -> tuple[bool, str]:
    module = EmailNotificationModule()
    try:
        module.send(999, MockEmailTransport())
    except ValueError as exc:
        return True, f"send rejected the unknown id: {exc}"
    return False, "sending an unknown notification id did not raise"


def _email_resend_is_idempotent() -> tuple[bool, str]:
    module = EmailNotificationModule()
    notification = module.create("student@example.com", "Subject", "Body")
    transport = MockEmailTransport()
    module.send(notification.notification_id, transport)
    delivered = len(transport.sent_messages)
    sent_again = module.send(notification.notification_id, transport)
    return (
        sent_again
        and notification.state == EmailState.SENT
        and len(transport.sent_messages) == delivered,
        (
            f"resend={sent_again}, state={notification.state.value}, "
            f"deliveries={len(transport.sent_messages)}"
        ),
    )


def _email_constraints_hold_when_sent() -> tuple[bool, str]:
    passed, errors = verify_constraints(
        EMAIL_CONSTRAINTS,
        {
            "valid_recipient": True,
            "sent": True,
            "was_queued": True,
            "retry_count": 0,
            "max_retry": 2,
        },
    )
    return passed, f"violations={errors or 'none'}"


def _email_constraints_detect_retry_overflow() -> tuple[bool, str]:
    passed, errors = verify_constraints(
        EMAIL_CONSTRAINTS,
        {
            "valid_recipient": True,
            "sent": False,
            "was_queued": True,
            "retry_count": 5,
            "max_retry": 2,
        },
    )
    detected = not passed and any("retry_limit" in error for error in errors)
    return detected, f"detected={detected}, violations={errors}"


# =============================================================
# VERIFICATION SCENARIOS
# =============================================================

def _kripke_model_is_reachable(function_name: str) -> tuple[bool, str]:
    function = _functions().get(function_name)
    if function is None:
        return False, f"specification for '{function_name}' was not found"

    model = build_kripke(function)
    errors = model.validate()
    reachable = _reachable_states(model)
    unreachable = sorted(set(model.states) - reachable)
    return (
        not errors and not unreachable,
        f"errors={errors or 'none'}, unreachable={unreachable or 'none'}",
    )


def _verification_auth_kripke() -> tuple[bool, str]:
    return _kripke_model_is_reachable("Authentication")


def _verification_email_kripke() -> tuple[bool, str]:
    return _kripke_model_is_reachable("EmailNotification")


def _verification_z3_locked_login_policy() -> tuple[bool, str]:
    status = check_locked_login_safety(max_attempts=3, min_password_length=8)
    return (
        status == "UNSAT",
        f"Z3 verdict for 'locked AND login_allowed' = {status}",
    )


def _verification_bmc_lockout_reachable() -> tuple[bool, str]:
    function = _functions().get("Authentication")
    if function is None:
        return False, "specification for 'Authentication' was not found"

    result = check_reachability(
        build_kripke(function),
        start="LOGGED_OUT",
        target="LOCKED",
        bound=4,
    )
    return (
        result.status == "SAT",
        (
            f"BMC {result.start}->{result.target} bound={result.bound} = "
            f"{result.status} ({result.detail})"
        ),
    )


def _verification_generated_code_matches_spec() -> tuple[bool, str]:
    function = _functions().get("Authentication")
    if function is None:
        return False, "specification for 'Authentication' was not found"

    with tempfile.TemporaryDirectory(prefix="lms-scenario-gen-") as directory:
        path = CodeGenerator().generate_state_enum(function, directory)
        expected = [state.name for state in function.states]
        errors = verify_generated_module(
            path,
            {state_enum_class_name(function.name): expected},
        )
    return not errors, f"errors={errors or 'none'}, states={expected}"


def _verification_safe_copy_model() -> tuple[bool, str]:
    counterexample = find_bounded_counterexample("safe", ANALYSIS_LENGTHS)
    return (
        counterexample is None,
        "no safe-model counterexample in lengths -32..32"
        if counterexample is None
        else f"unexpected counterexample at length={counterexample.length}",
    )


def _verification_vulnerable_copy_model() -> tuple[bool, str]:
    counterexample = find_bounded_counterexample("vulnerable", ANALYSIS_LENGTHS)
    return (
        counterexample is not None,
        f"counterexample length={counterexample.length}"
        if counterexample is not None
        else "the vulnerable model did not expose a counterexample",
    )


# =============================================================
# CROSS-FUNCTION JOURNEY
# =============================================================

def _journey_register_login_notify_logout() -> tuple[bool, str]:
    auth = AuthenticationModule()
    auth.register("e2e-user", "SecurePass123")
    session = auth.login("e2e-user", "SecurePass123")
    if session is None:
        return False, "login did not issue a session"

    email = EmailNotificationModule()
    notification = email.create("e2e-user@example.com", "Welcome", "LMS journey")
    sent = email.send(notification.notification_id, MockEmailTransport())
    logged_out = auth.logout(session.token)
    return (
        sent
        and logged_out
        and notification.state == EmailState.SENT
        and auth.authenticate(session.token) is None,
        (
            f"sent={sent}, logout={logged_out}, "
            f"notification={notification.state.value}, "
            f"session_invalidated={auth.authenticate(session.token) is None}"
        ),
    )


SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        id="AUTH-01",
        function="Authentication",
        title="Đăng ký rồi đăng nhập hợp lệ",
        steps=(
            "register('scenario-user', 'SecurePass123')",
            "login('scenario-user', 'SecurePass123')",
            "authenticate(token)",
        ),
        expected="User ở LOGGED_IN và token xác thực đúng user",
        check=_auth_valid_login,
    ),
    Scenario(
        id="AUTH-02",
        function="Authentication",
        title="Sai mật khẩu → LOGIN_FAILED",
        steps=("register hợp lệ", "login với mật khẩu sai"),
        expected="Không có session, state=LOGIN_FAILED, failed_attempts=1",
        check=_auth_wrong_password,
    ),
    Scenario(
        id="AUTH-03",
        function="Authentication",
        title="Khoá tài khoản sau max_attempts",
        steps=("register", "login sai 3 lần"),
        expected="state=LOCKED và failed_attempts=max_attempts",
        check=_auth_lockout_after_max_attempts,
    ),
    Scenario(
        id="AUTH-04",
        function="Authentication",
        title="Tài khoản LOCKED từ chối cả mật khẩu đúng",
        steps=("login sai 3 lần", "login lại bằng mật khẩu đúng"),
        expected="Không cấp session, state vẫn LOCKED",
        check=_auth_locked_rejects_correct_password,
    ),
    Scenario(
        id="AUTH-05",
        function="Authentication",
        title="Logout vô hiệu hoá session hiện tại",
        steps=("register", "login", "logout(token)"),
        expected="logout=True và token không còn xác thực",
        check=_auth_logout_invalidates_session,
    ),
    Scenario(
        id="AUTH-06",
        function="Authentication",
        title="Logout thu hồi toàn bộ session của user",
        steps=("login 2 session", "logout session thứ nhất", "login lại"),
        expected="Session còn lại bị thu hồi vĩnh viễn",
        check=_auth_logout_revokes_all_sessions,
    ),
    Scenario(
        id="AUTH-07",
        function="Authentication",
        title="Mật khẩu ngắn hơn min_password_length bị từ chối",
        steps=("register với mật khẩu 5 ký tự",),
        expected="ValueError được raise",
        check=_auth_short_password_rejected,
    ),
    Scenario(
        id="AUTH-08",
        function="Authentication",
        title="Username trùng bị từ chối",
        steps=("register lần 1", "register lại cùng username"),
        expected="ValueError được raise ở lần đăng ký thứ hai",
        check=_auth_duplicate_username_rejected,
    ),
    Scenario(
        id="AUTH-09",
        function="Authentication",
        title="User không tồn tại không tạo session",
        steps=("login với username chưa đăng ký",),
        expected="Trả None và không tạo session nào",
        check=_auth_unknown_user_rejected,
    ),
    Scenario(
        id="AUTH-10",
        function="Authentication",
        title="Session hết hạn không xác thực được",
        steps=("register", "login với session_ttl_seconds=0", "authenticate(token)"),
        expected="authenticate trả None",
        check=_auth_expired_session_rejected,
    ),
    Scenario(
        id="AUTH-11",
        function="Authentication",
        title="reset_lock mở khoá và cho đăng nhập lại",
        steps=("login sai 3 lần", "reset_lock", "login bằng mật khẩu đúng"),
        expected="state=LOGGED_IN và có session mới",
        check=_auth_reset_lock_restores_access,
    ),
    Scenario(
        id="AUTH-12",
        function="Authentication",
        title="Hash mật khẩu có salt ngẫu nhiên",
        steps=("hash_password 2 lần cùng mật khẩu", "verify_password cả hai"),
        expected="Hai hash khác nhau và đều verify đúng",
        check=_auth_password_hashes_are_salted,
    ),
    Scenario(
        id="AUTH-13",
        function="Authentication",
        title="Hash có tham số yếu bị từ chối",
        steps=("hạ PBKDF2 iteration count xuống 1", "verify_password"),
        expected="verify_password trả False",
        check=_auth_weak_hash_parameters_rejected,
    ),
    Scenario(
        id="AUTH-14",
        function="Authentication",
        title="Ràng buộc auth đúng sau khi đăng nhập",
        steps=("login hợp lệ", "verify_constraints(AUTH_CONSTRAINTS, context)"),
        expected="Không có vi phạm ràng buộc",
        check=_auth_constraints_hold_after_login,
    ),
    Scenario(
        id="AUTH-15",
        function="Authentication",
        title="Ràng buộc phát hiện LOCKED nhưng vẫn cho login",
        steps=("verify_constraints với state=LOCKED, login_allowed=True",),
        expected="Phát hiện vi phạm locked_cannot_login",
        check=_auth_constraints_detect_locked_login,
    ),
    Scenario(
        id="EMAIL-01",
        function="EmailNotification",
        title="Tạo và gửi notification thành công",
        steps=("create(recipient hợp lệ)", "send với transport thành công"),
        expected="State QUEUED → SENT",
        check=_email_successful_delivery,
    ),
    Scenario(
        id="EMAIL-02",
        function="EmailNotification",
        title="Recipient không hợp lệ bị từ chối",
        steps=("create('not-an-email', ...)",),
        expected="ValueError được raise",
        check=_email_invalid_recipient_rejected,
    ),
    Scenario(
        id="EMAIL-03",
        function="EmailNotification",
        title="Lỗi tạm thời rồi retry thành công",
        steps=("send với transport lỗi", "send lại với transport thành công"),
        expected="retry_count=1 và state=SENT",
        check=_email_transient_failure_then_retry,
    ),
    Scenario(
        id="EMAIL-04",
        function="EmailNotification",
        title="Vượt retry limit → FAILED",
        steps=("max_retry=2", "send lỗi 3 lần"),
        expected="retry_count=max_retry=2 và state=FAILED",
        check=_email_retry_limit_exceeded,
    ),
    Scenario(
        id="EMAIL-05",
        function="EmailNotification",
        title="Gửi notification không tồn tại bị từ chối",
        steps=("send(999, transport)",),
        expected="ValueError được raise",
        check=_email_unknown_notification_rejected,
    ),
    Scenario(
        id="EMAIL-06",
        function="EmailNotification",
        title="Gửi lại notification đã SENT là idempotent",
        steps=("send thành công", "send lại cùng notification"),
        expected="state vẫn SENT và không gửi thêm lần nào",
        check=_email_resend_is_idempotent,
    ),
    Scenario(
        id="EMAIL-07",
        function="EmailNotification",
        title="Ràng buộc email đúng khi đã SENT",
        steps=("verify_constraints(EMAIL_CONSTRAINTS, context hợp lệ)",),
        expected="Không có vi phạm ràng buộc",
        check=_email_constraints_hold_when_sent,
    ),
    Scenario(
        id="EMAIL-08",
        function="EmailNotification",
        title="Ràng buộc phát hiện retry vượt max_retry",
        steps=("verify_constraints với retry_count=5, max_retry=2",),
        expected="Phát hiện vi phạm retry_limit",
        check=_email_constraints_detect_retry_overflow,
    ),
    Scenario(
        id="VER-01",
        function="Verification",
        title="Kripke Authentication hợp lệ và mọi state đều reachable",
        steps=("build_kripke(Authentication)", "validate()", "duyệt successors"),
        expected="Không có lỗi cấu trúc và không có state không reachable",
        check=_verification_auth_kripke,
    ),
    Scenario(
        id="VER-02",
        function="Verification",
        title="Kripke EmailNotification hợp lệ và mọi state đều reachable",
        steps=("build_kripke(EmailNotification)", "validate()", "duyệt successors"),
        expected="Không có lỗi cấu trúc và không có state không reachable",
        check=_verification_email_kripke,
    ),
    Scenario(
        id="VER-03",
        function="Verification",
        title="Z3 chứng minh policy 'LOCKED không được login' (UNSAT)",
        steps=("assert locked=true và login_allowed=true", "solver.check()"),
        expected="UNSAT — không tồn tại model vi phạm",
        check=_verification_z3_locked_login_policy,
    ),
    Scenario(
        id="VER-04",
        function="Verification",
        title="BMC chứng minh LOCKED reachable từ LOGGED_OUT (SAT)",
        steps=("unroll bound=4", "check_reachability(LOGGED_OUT → LOCKED)"),
        expected="SAT kèm witness path",
        check=_verification_bmc_lockout_reachable,
    ),
    Scenario(
        id="VER-05",
        function="Verification",
        title="Mã sinh ra khớp state trong spec",
        steps=("generate_state_enum", "import module", "so khớp enum members"),
        expected="Không có sai khác giữa spec và mã sinh",
        check=_verification_generated_code_matches_spec,
    ),
    Scenario(
        id="VER-06",
        function="Verification",
        title="Mô hình C an toàn không có counterexample",
        steps=("find_bounded_counterexample('safe', -32..32)",),
        expected="None — không có vi phạm trong miền bounded",
        check=_verification_safe_copy_model,
    ),
    Scenario(
        id="VER-07",
        function="Verification",
        title="Mô hình C lỗi có counterexample",
        steps=("find_bounded_counterexample('vulnerable', -32..32)",),
        expected="Tìm thấy counterexample (length=-1)",
        check=_verification_vulnerable_copy_model,
    ),
    Scenario(
        id="E2E-01",
        function="End-to-end",
        title="Hành trình LMS: đăng ký → đăng nhập → gửi email → logout",
        steps=(
            "register + login",
            "create + send notification",
            "logout(session)",
        ),
        expected="Email SENT và session bị vô hiệu hoá sau logout",
        check=_journey_register_login_notify_logout,
    ),
)


def scenario_catalogue() -> list[dict[str, Any]]:
    """Return the declared scenarios as UI-friendly rows (no execution)."""
    return [
        {
            "ID": scenario.id,
            "Function": scenario.function,
            "Scenario": scenario.title,
            "Steps": " → ".join(scenario.steps),
            "Expected": scenario.expected,
        }
        for scenario in SCENARIOS
    ]


def run_e2e_scenarios() -> list[dict[str, Any]]:
    """Execute every declared scenario and return PASS/FAIL evidence."""
    results: list[dict[str, Any]] = []
    for scenario in SCENARIOS:
        try:
            passed, evidence = scenario.check()
        except Exception as exc:  # noqa: BLE001 - a scenario must never crash the run
            passed, evidence = False, f"unexpected exception: {exc!r}"

        results.append(
            {
                "ID": scenario.id,
                "Function": scenario.function,
                "Scenario": scenario.title,
                "Expected": scenario.expected,
                "Result": "PASS" if passed else "FAIL",
                "Evidence": evidence,
            }
        )
    return results
