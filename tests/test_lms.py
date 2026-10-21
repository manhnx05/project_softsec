import pytest

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
from src.modules.rbac_approval import (
    ApprovalState,
    IllegalStateTransitionError,
    PermissionDeniedError,
    RBACApprovalModule,
    Role,
    create_approval_state_machine,
)
from src.specification.loader import load_test_scenarios
from src.verification.kripke import build_auth_kripke, build_email_kripke


# =============================================================
# AUTHENTICATION TESTS
# =============================================================

def test_register_and_login():

    auth = AuthenticationModule()

    user = auth.register(
        "student",
        "password123"
    )

    session = auth.login(
        "student",
        "password123"
    )

    assert user.state == AuthState.LOGGED_IN

    assert session is not None

    assert (
        auth.authenticate(
            session.token
        )
        is user
    )


def test_wrong_password():

    auth = AuthenticationModule()

    user = auth.register(
        "student",
        "password123"
    )

    session = auth.login(
        "student",
        "wrong"
    )

    assert session is None

    assert (
        user.state
        == AuthState.LOGIN_FAILED
    )

    assert user.failed_attempts == 1


def test_account_locked_after_max_attempts():

    auth = AuthenticationModule()

    user = auth.register(
        "student",
        "password123"
    )

    for _ in range(3):

        auth.login(
            "student",
            "wrong"
        )

    assert (
        user.state
        == AuthState.LOCKED
    )

    assert user.failed_attempts == 3


def test_locked_account_cannot_login():

    auth = AuthenticationModule()

    user = auth.register(
        "student",
        "password123"
    )

    # Login sai 3 lần

    for _ in range(3):

        auth.login(
            "student",
            "wrong"
        )

    # Sau khi LOCKED,
    # password đúng cũng không login được

    session = auth.login(
        "student",
        "password123"
    )

    assert session is None

    assert (
        user.state
        == AuthState.LOCKED
    )


def test_logout_invalidates_session():

    auth = AuthenticationModule()

    auth.register(
        "student",
        "password123"
    )

    session = auth.login(
        "student",
        "password123"
    )

    assert session is not None

    result = auth.logout(
        session.token
    )

    assert result is True

    assert (
        auth.authenticate(
            session.token
        )
        is None
    )


def test_logout_revokes_all_sessions_permanently():

    auth = AuthenticationModule()
    auth.register("student", "password123")

    logged_out_session = auth.login("student", "password123")
    remaining_session = auth.login("student", "password123")

    assert logged_out_session is not None
    assert remaining_session is not None
    assert auth.logout(logged_out_session.token) is True
    assert auth.authenticate(remaining_session.token) is None

    new_session = auth.login("student", "password123")

    assert new_session is not None
    assert auth.authenticate(remaining_session.token) is None


def test_short_password_rejected():

    auth = AuthenticationModule()

    with pytest.raises(ValueError):

        auth.register(
            "student",
            "123"
        )


def test_password_hash_uses_unique_salts_and_verifies_password():

    first_hash = hash_password("password123")
    second_hash = hash_password("password123")

    assert first_hash != second_hash
    assert first_hash.startswith("pbkdf2_sha256$600000$")
    assert verify_password("password123", first_hash) is True
    assert verify_password("wrong-password", first_hash) is False


def test_password_verification_rejects_malformed_hash():

    assert verify_password("password123", "invalid-hash") is False


# =============================================================
# EMAIL TESTS
# =============================================================

def test_email_success():

    email = EmailNotificationModule()

    notification = email.create(

        "student@example.com",

        "Test",

        "Hello"
    )

    transport = MockEmailTransport(
        should_fail=False
    )

    result = email.send(

        notification.notification_id,

        transport
    )

    assert result is True

    assert (
        notification.state
        == EmailState.SENT
    )

    assert len(
        transport.sent_messages
    ) == 1


def test_email_retry():

    email = EmailNotificationModule()

    notification = email.create(

        "student@example.com",

        "Test",

        "Hello"
    )

    transport = MockEmailTransport(
        should_fail=True
    )

    result = email.send(

        notification.notification_id,

        transport
    )

    assert result is False

    assert (
        notification.retry_count
        == 1
    )

    assert (
        notification.state
        == EmailState.QUEUED
    )


def test_invalid_email():

    email = EmailNotificationModule()

    with pytest.raises(ValueError):

        email.create(

            "invalid-email",

            "Test",

            "Hello"
        )


# =============================================================
# KRIPKE TESTS
# =============================================================

def test_auth_kripke():

    model = build_auth_kripke()

    # Kripke phải hợp lệ

    assert model.validate() == []

    # LOGGED_OUT có thể chuyển sang LOGGED_IN

    assert (
        "LOGGED_IN"
        in model.successors(
            "LOGGED_OUT"
        )
    )

    # LOGIN_FAILED có thể chuyển sang LOCKED

    assert (
        "LOCKED"
        in model.successors(
            "LOGIN_FAILED"
        )
    )


def test_email_kripke():

    model = build_email_kripke()

    assert model.validate() == []

    assert (
        model.successors("IDLE")
        == {"QUEUED"}
    )

    assert (
        "SENT"
        in model.successors("QUEUED")
    )

    assert (
        "FAILED"
        in model.successors("QUEUED")
    )


# =============================================================
# SCENARIO MATRIX: LOGIC & STATE MACHINE TESTS
# =============================================================

def test_scenario_matrix_contains_all_required_logic_scenarios():
    """Kiểm tra ma trận test_scenarios.yaml chứa đầy đủ kịch bản cấp Logic."""
    scenarios = load_test_scenarios()
    logic_ids = {s.id for s in scenarios if s.level == "Logic"}
    assert "TS-LOGIC-AUTH-001" in logic_ids
    assert "TS-LOGIC-EMAIL-001" in logic_ids
    assert "TS-LOGIC-RBAC-001" in logic_ids


def test_scenario_logic_auth_account_lockout_consecutive_failures():
    """
    Kịch bản TS-LOGIC-AUTH-001:
    Khóa tài khoản sau N lần nhập sai mật khẩu liên tiếp (ACTIVE/LOGGED_OUT -> LOCKED).
    Khi đã LOCKED, mật khẩu đúng vẫn không được phép đăng nhập (CWE-307 Brute Force).
    """
    scenarios = load_test_scenarios()
    scenario = next(s for s in scenarios if s.id == "TS-LOGIC-AUTH-001")
    assert scenario.level == "Logic"
    assert "CWE-307" in scenario.hazard_type

    # Cấu hình tham số N lần thất bại (ví dụ N = 3)
    n_max_attempts = 3
    auth = AuthenticationModule(params=LoginParams(max_attempts=n_max_attempts))
    user = auth.register("student_sec", "P@ssword123")
    assert user.state == AuthState.LOGGED_OUT
    assert user.failed_attempts == 0

    # Lần 1: Sai mật khẩu -> LOGIN_FAILED, failed_attempts = 1
    session_1 = auth.login("student_sec", "wrong_1")
    assert session_1 is None
    assert user.state == AuthState.LOGIN_FAILED
    assert user.failed_attempts == 1

    # Lần 2: Sai mật khẩu -> LOGIN_FAILED, failed_attempts = 2
    session_2 = auth.login("student_sec", "wrong_2")
    assert session_2 is None
    assert user.state == AuthState.LOGIN_FAILED
    assert user.failed_attempts == 2

    # Lần 3 (Lần thứ N): Sai mật khẩu -> Chuyển sang LOCKED, failed_attempts = 3
    session_3 = auth.login("student_sec", "wrong_3")
    assert session_3 is None
    assert user.state == AuthState.LOCKED
    assert user.failed_attempts == n_max_attempts

    # Lần 4: Thử đăng nhập bằng mật khẩu đúng -> Vẫn bị từ chối, tài khoản giữ nguyên LOCKED
    session_4 = auth.login("student_sec", "P@ssword123")
    assert session_4 is None
    assert user.state == AuthState.LOCKED


def test_scenario_logic_email_retry_exhaustion_to_failed():
    """
    Kịch bản TS-LOGIC-EMAIL-001:
    Luồng gửi email thất bại và thử lại (Retry logic).
    Chuyển trạng thái: QUEUED -> (thử lại) -> FAILED khi retry_count > max_retries.
    """
    scenarios = load_test_scenarios()
    scenario = next(s for s in scenarios if s.id == "TS-LOGIC-EMAIL-001")
    assert scenario.level == "Logic"
    assert "CWE-834" in scenario.hazard_type

    max_retry = 2
    email_module = EmailNotificationModule(params=EmailParams(max_retry=max_retry))
    notification = email_module.create(
        recipient="learner@university.edu",
        subject="Security Notification",
        body="Alert details",
    )
    assert notification.state == EmailState.QUEUED
    assert notification.retry_count == 0

    transport_fail = MockEmailTransport(should_fail=True)

    # Thử gửi lần 1: Thất bại -> retry_count = 1, vẫn QUEUED (được retry tiếp)
    res_1 = email_module.send(notification.notification_id, transport_fail)
    assert res_1 is False
    assert notification.retry_count == 1
    assert notification.state == EmailState.QUEUED

    # Thử gửi lần 2: Thất bại -> retry_count = 2, vẫn QUEUED (đạt ngưỡng retry)
    res_2 = email_module.send(notification.notification_id, transport_fail)
    assert res_2 is False
    assert notification.retry_count == 2
    assert notification.state == EmailState.QUEUED

    # Thử gửi lần 3: Thất bại (vượt quá max_retry=2) -> Chuyển sang FAILED
    res_3 = email_module.send(notification.notification_id, transport_fail)
    assert res_3 is False
    assert notification.retry_count == 3
    assert notification.state == EmailState.FAILED

    # Thử gửi lần 4: Khi đã FAILED, không thể gửi tiếp
    res_4 = email_module.send(notification.notification_id, transport_fail)
    assert res_4 is False
    assert notification.state == EmailState.FAILED


def test_scenario_logic_rbac_illegal_state_transition_bypass_blocked():
    """
    Kịch bản TS-LOGIC-RBAC-001:
    Phân quyền (RBAC) & Chuyển trạng thái bất hợp lệ.
    Chặn đứng hành vi nhảy cóc từ PENDING thẳng sang APPROVED mà bỏ qua STEP_VERIFY.
    """
    scenarios = load_test_scenarios()
    scenario = next(s for s in scenarios if s.id == "TS-LOGIC-RBAC-001")
    assert scenario.level == "Logic"
    assert "CWE-841" in scenario.hazard_type

    # 1. Kiểm tra trên mô hình State Machine hình thức
    sm = create_approval_state_machine()
    assert sm.current_state == ApprovalState.PENDING.value

    # Trong đồ thị trạng thái, PENDING chỉ có thể chuyển sang STEP_VERIFY
    available_events = [t.event for t in sm.available_transitions()]
    assert "verify_step" in available_events
    assert "approve" not in available_events
    assert sm.can_transition("approve") is False

    # Thử ép chuyển thẳng từ PENDING sang APPROVED trên máy trạng thái
    transition_success = sm.transition("approve")
    assert transition_success is False
    assert sm.current_state == ApprovalState.PENDING.value

    # 2. Kiểm tra trên nghiệp vụ RBAC Approval Module
    rbac_module = RBACApprovalModule()
    req = rbac_module.submit_request("REQ-2026-001", "student_alice")
    assert req.state == ApprovalState.PENDING

    # Hacker / Sinh viên cố gắng gọi approve trực tiếp từ PENDING
    with pytest.raises(IllegalStateTransitionError, match="STEP_VERIFY"):
        rbac_module.approve("REQ-2026-001", actor_role=Role.STUDENT, actor_name="student_alice")

    # Kể cả ADMIN nếu gọi approve trực tiếp khi chưa qua STEP_VERIFY cũng bị chặn
    with pytest.raises(IllegalStateTransitionError, match="STEP_VERIFY"):
        rbac_module.approve("REQ-2026-001", actor_role=Role.ADMIN, actor_name="admin_root")

    assert req.state == ApprovalState.PENDING


def test_scenario_logic_rbac_authorized_progression_with_role_checks():
    """
    Kiểm tra phân quyền nghiêm ngặt theo vai trò:
    - STUDENT không được tự verify hoặc approve
    - AUDITOR chỉ được verify
    - ADMIN được approve sau khi AUDITOR đã verify
    """
    rbac_module = RBACApprovalModule()
    req = rbac_module.submit_request("REQ-2026-002", "student_bob")

    # Sinh viên không có quyền verify
    with pytest.raises(PermissionDeniedError):
        rbac_module.verify_step("REQ-2026-002", actor_role=Role.STUDENT, actor_name="student_bob")

    # Auditor thẩm định hồ sơ hợp lệ: PENDING -> STEP_VERIFY
    assert rbac_module.verify_step("REQ-2026-002", actor_role=Role.AUDITOR, actor_name="auditor_jane") is True
    assert req.state == ApprovalState.STEP_VERIFY
    assert req.verified_by == "auditor_jane"

    # Auditor không có quyền phê duyệt chung cuộc (chỉ ADMIN mới có)
    with pytest.raises(PermissionDeniedError):
        rbac_module.approve("REQ-2026-002", actor_role=Role.AUDITOR, actor_name="auditor_jane")

    # Admin phê duyệt hợp lệ: STEP_VERIFY -> APPROVED
    assert rbac_module.approve("REQ-2026-002", actor_role=Role.ADMIN, actor_name="admin_super") is True
    assert req.state == ApprovalState.APPROVED
    assert req.approved_by == "admin_super"