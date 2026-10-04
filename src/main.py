from pathlib import Path

from src.modules.authentication import (
    AuthenticationModule,
    LoginParams
)

from src.modules.email_notification import (
    EmailNotificationModule,
    EmailParams,
    MockEmailTransport
)

from src.verification.kripke import (
    build_auth_kripke,
    build_email_kripke,
    print_kripke
)

from src.verification.constraints import (
    AUTH_CONSTRAINTS,
    EMAIL_CONSTRAINTS,
    verify_constraints
)

from src.generation.generator import (
    generate_states
)


# =============================================================
# 1. AUTHENTICATION DYNAMIC TEST
# =============================================================

def run_authentication_demo():

    print("\n" + "=" * 60)

    print(
        "1. AUTHENTICATION - DYNAMIC TEST"
    )

    print("=" * 60)

    # ---------------------------------------------------------
    # Tạo Authentication Module
    # ---------------------------------------------------------

    auth = AuthenticationModule(

        LoginParams(

            max_attempts=3,

            session_ttl_seconds=3600,

            min_password_length=8
        )
    )

    # ---------------------------------------------------------
    # Register
    # ---------------------------------------------------------

    user = auth.register(

        "student",

        "password123"
    )

    print(
        "Register:",
        user.username
    )

    print(
        "State:",
        user.state.value
    )

    # ---------------------------------------------------------
    # Login đúng
    # ---------------------------------------------------------

    session = auth.login(

        "student",

        "password123"
    )

    print("\nCorrect login:")

    print(
        "Session created:",
        session is not None
    )

    print(
        "State:",
        user.state.value
    )

    # ---------------------------------------------------------
    # Authenticate session
    # ---------------------------------------------------------

    if session:

        current_user = auth.authenticate(
            session.token
        )

        print(
            "Authenticate:",
            current_user.username
            if current_user
            else None
        )

        # -----------------------------------------------------
        # Logout
        # -----------------------------------------------------

        auth.logout(
            session.token
        )

        print(
            "After logout:",
            user.state.value
        )

    # ---------------------------------------------------------
    # Wrong password
    # ---------------------------------------------------------

    print(
        "\nWrong password 3 times:"
    )

    for i in range(3):

        result = auth.login(

            "student",

            "wrong-password"
        )

        print(
            f"Attempt {i + 1}: "
            f"result={result}, "
            f"state={user.state.value}, "
            f"failed={user.failed_attempts}"
        )


# =============================================================
# 2. EMAIL DYNAMIC TEST
# =============================================================

def run_email_demo():

    print("\n" + "=" * 60)

    print(
        "2. EMAIL NOTIFICATION - DYNAMIC TEST"
    )

    print("=" * 60)

    # ---------------------------------------------------------
    # Tạo Email Module
    # ---------------------------------------------------------

    email = EmailNotificationModule(

        EmailParams(
            max_retry=2
        )
    )

    # ---------------------------------------------------------
    # Create notification
    # ---------------------------------------------------------

    notification = email.create(

        recipient="student@example.com",

        subject="LMS Notification",

        body="Bạn có thông báo mới."
    )

    print("Created:")

    print(
        "ID:",
        notification.notification_id
    )

    print(
        "State:",
        notification.state.value
    )

    # ---------------------------------------------------------
    # Mock transport
    # ---------------------------------------------------------

    transport = MockEmailTransport(
        should_fail=False
    )

    # ---------------------------------------------------------
    # Send
    # ---------------------------------------------------------

    result = email.send(

        notification.notification_id,

        transport
    )

    print(
        "\nSend result:",
        result
    )

    print(
        "State:",
        notification.state.value
    )


# =============================================================
# 3. CONSTRAINT VERIFICATION
# =============================================================

def run_constraint_demo():

    print("\n" + "=" * 60)

    print(
        "3. CONSTRAINT VERIFICATION"
    )

    print("=" * 60)

    # ---------------------------------------------------------
    # Authentication context
    # ---------------------------------------------------------

    from src.models.states import AuthState

    auth_context = {

        "password":
            "password123",

        "min_password_length":
            8,

        "state":
            AuthState.LOGGED_IN,

        "login_allowed":
            True,

        "failed_attempts":
            0,

        "max_attempts":
            3,

        "session_valid":
            True
    }

    # ---------------------------------------------------------
    # Verify Authentication
    # ---------------------------------------------------------

    ok, errors = verify_constraints(

        AUTH_CONSTRAINTS,

        auth_context
    )

    print(
        "Authentication constraints:",
        "PASS" if ok else "FAIL"
    )

    for error in errors:

        print(
            "  ",
            error
        )

    # ---------------------------------------------------------
    # Email context
    # ---------------------------------------------------------

    email_context = {

        "valid_recipient":
            True,

        "sent":
            True,

        "was_queued":
            True,

        "retry_count":
            0,

        "max_retry":
            2
    }

    # ---------------------------------------------------------
    # Verify Email
    # ---------------------------------------------------------

    ok, errors = verify_constraints(

        EMAIL_CONSTRAINTS,

        email_context
    )

    print(
        "Email constraints:",
        "PASS" if ok else "FAIL"
    )

    for error in errors:

        print(
            "  ",
            error
        )


# =============================================================
# 4. KRIPKE MODEL
# =============================================================

def run_kripke_demo():

    print("\n" + "=" * 60)

    print(
        "4. KRIPKE MODEL"
    )

    print("=" * 60)

    # ---------------------------------------------------------
    # Build Authentication Kripke
    # ---------------------------------------------------------

    auth_model = build_auth_kripke()

    # ---------------------------------------------------------
    # Build Email Kripke
    # ---------------------------------------------------------

    email_model = build_email_kripke()

    # ---------------------------------------------------------
    # Print Authentication
    # ---------------------------------------------------------

    print_kripke(

        auth_model,

        "AUTHENTICATION KRIPKE"
    )

    # ---------------------------------------------------------
    # Print Email
    # ---------------------------------------------------------

    print_kripke(

        email_model,

        "EMAIL KRIPKE"
    )

    return (
        auth_model,
        email_model
    )


# =============================================================
# 5. CODE GENERATION
# =============================================================

def run_code_generation(
    auth_model,
    email_model
):

    print("\n" + "=" * 60)

    print(
        "5. CODE GENERATION"
    )

    print("=" * 60)

    output = Path(
        "generated_states.py"
    )

    generate_states(

        {
            "AuthStateGenerated":
                auth_model,

            "EmailStateGenerated":
                email_model
        },

        output
    )

    print(
        "[OK] Generated:",
        output.resolve()
    )


# =============================================================
# MAIN
# =============================================================

def main():

    print("=" * 60)

    print(
        "LMS END-TO-END SOFTWARE SECURITY DEMO"
    )

    print("=" * 60)

    # ---------------------------------------------------------
    # Pipeline
    # ---------------------------------------------------------

    print("\nPIPELINE:")

    print(
        "FUNCTION -> PARAMETERS -> STATES -> "
        "CONSTRAINTS -> KRIPKE -> CODE GENERATION "
        "-> STATIC TEST -> DYNAMIC TEST"
    )

    # ---------------------------------------------------------
    # Constraint
    # ---------------------------------------------------------

    run_constraint_demo()

    # ---------------------------------------------------------
    # Kripke
    # ---------------------------------------------------------

    auth_model, email_model = (
        run_kripke_demo()
    )

    # ---------------------------------------------------------
    # Code generation
    # ---------------------------------------------------------

    run_code_generation(

        auth_model,

        email_model
    )

    # ---------------------------------------------------------
    # Dynamic test
    # ---------------------------------------------------------

    run_authentication_demo()

    run_email_demo()

    print("\nDONE.")


# =============================================================
# PROGRAM ENTRY
# =============================================================

if __name__ == "__main__":

    main()