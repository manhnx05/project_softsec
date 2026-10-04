import pytest

from src.models.states import AuthState, EmailState
from src.modules.authentication import (
    AuthenticationModule,
    hash_password,
    verify_password,
)
from src.modules.email_notification import EmailNotificationModule, MockEmailTransport
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