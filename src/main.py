from pathlib import Path

from src.generation.generator import (
    CodeGenerator,
    state_enum_class_name,
    verify_generated_module,
)
from src.models.states import AuthState
from src.modules.authentication import AuthenticationModule, LoginParams
from src.modules.email_notification import (
    EmailNotificationModule,
    EmailParams,
    MockEmailTransport,
)
from src.specification.schemas import FunctionSpec, StateSpec
from src.verification.constraints import (
    AUTH_CONSTRAINTS,
    EMAIL_CONSTRAINTS,
    verify_constraints,
)
from src.verification.kripke import (
    KripkeModel,
    build_auth_kripke,
    build_email_kripke,
    print_kripke,
)


def run_authentication_demo() -> None:
    auth = AuthenticationModule(
        LoginParams(
            max_attempts=3,
            session_ttl_seconds=3600,
            min_password_length=8,
        )
    )
    user = auth.register("student", "password123")
    session = auth.login("student", "password123")
    print(f"Registered {user.username}; login succeeded: {session is not None}")

    if session is not None:
        print(f"Session authenticates: {auth.authenticate(session.token) is user}")
        auth.logout(session.token)

    for attempt in range(1, 4):
        result = auth.login("student", "wrong-password")
        print(
            f"Attempt {attempt}: result={result}, state={user.state.value}, "
            f"failed={user.failed_attempts}"
        )


def run_email_demo() -> None:
    email = EmailNotificationModule(EmailParams(max_retry=2))
    notification = email.create(
        recipient="student@example.com",
        subject="LMS Notification",
        body="You have a new notification.",
    )
    sent = email.send(
        notification.notification_id,
        MockEmailTransport(),
    )
    print(f"Email sent: {sent}; state={notification.state.value}")


def run_constraint_demo() -> None:
    auth_context = {
        "password": "password123",
        "min_password_length": 8,
        "state": AuthState.LOGGED_IN,
        "login_allowed": True,
        "failed_attempts": 0,
        "max_attempts": 3,
        "session_valid": True,
    }
    email_context = {
        "valid_recipient": True,
        "sent": True,
        "was_queued": True,
        "retry_count": 0,
        "max_retry": 2,
    }

    for label, constraints, context in (
        ("Authentication", AUTH_CONSTRAINTS, auth_context),
        ("Email", EMAIL_CONSTRAINTS, email_context),
    ):
        passed, errors = verify_constraints(constraints, context)
        print(f"{label} constraints: {'PASS' if passed else 'FAIL'}")
        for error in errors:
            print(f"  {error}")


def run_kripke_demo() -> tuple[KripkeModel, KripkeModel]:
    auth_model = build_auth_kripke()
    email_model = build_email_kripke()
    print_kripke(auth_model, "AUTHENTICATION KRIPKE")
    print_kripke(email_model, "EMAIL KRIPKE")
    return auth_model, email_model


def run_code_generation(
    auth_model: KripkeModel,
    email_model: KripkeModel,
) -> list[Path]:
    generator = CodeGenerator()
    output_dir = Path("generated")
    generated_files = []
    verification_errors: list[str] = []

    for name, model in (("Auth", auth_model), ("Email", email_model)):
        state_names = [state.name for state in model.states.values()]
        function = FunctionSpec(
            name=name,
            states=[StateSpec(name=state_name) for state_name in state_names],
        )
        generated_file = generator.generate_state_enum(function, str(output_dir))
        generated_files.append(generated_file)

        errors = verify_generated_module(
            generated_file,
            {state_enum_class_name(name): state_names},
        )
        verification_errors.extend(
            f"{generated_file.name}: {error}" for error in errors
        )

    for generated_file in generated_files:
        print(f"Generated: {generated_file.resolve()}")

    if verification_errors:
        for error in verification_errors:
            print(f"[FAIL] {error}")
        print("Generated module verification: FAIL")
    else:
        print("Generated module verification: PASS")

    return generated_files


def main() -> None:
    print("LMS END-TO-END SOFTWARE SECURITY DEMO")
    run_constraint_demo()
    auth_model, email_model = run_kripke_demo()
    run_code_generation(auth_model, email_model)
    run_authentication_demo()
    run_email_demo()


if __name__ == "__main__":
    main()