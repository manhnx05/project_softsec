"""Kripke models for the LMS workflows.

This module builds Kripke structures on top of the single canonical
``src.kripke.model.KripkeModel`` definition so the UI, tests, and
verification code all share one representation.
"""

from src.kripke.model import KripkeModel

# =============================================================
# AUTHENTICATION KRIPKE
# =============================================================

def build_auth_kripke() -> KripkeModel:

    model = KripkeModel()

    model.add_state(
        "LOGGED_OUT",
        {"not_authenticated"},
    )
    model.add_state(
        "LOGIN_FAILED",
        {"authentication_failed"},
    )
    model.add_state(
        "LOGGED_IN",
        {"authenticated", "session_valid"},
    )
    model.add_state(
        "LOCKED",
        {"account_locked"},
    )

    model.add_transition(
        "LOGGED_OUT",
        "LOGGED_IN",
        "correct_password",
    )
    model.add_transition(
        "LOGGED_OUT",
        "LOGIN_FAILED",
        "wrong_password",
    )
    model.add_transition(
        "LOGIN_FAILED",
        "LOGIN_FAILED",
        "wrong_password",
    )
    model.add_transition(
        "LOGIN_FAILED",
        "LOGGED_IN",
        "correct_password",
    )
    model.add_transition(
        "LOGIN_FAILED",
        "LOCKED",
        "max_attempts",
    )
    model.add_transition(
        "LOGGED_IN",
        "LOGGED_OUT",
        "logout",
    )
    model.add_transition(
        "LOCKED",
        "LOGGED_OUT",
        "reset_lock",
    )

    model.initial_state = "LOGGED_OUT"

    return model


# =============================================================
# EMAIL KRIPKE
# =============================================================

def build_email_kripke() -> KripkeModel:

    model = KripkeModel()

    model.add_state("IDLE", {"not_queued"})
    model.add_state("QUEUED", {"queued"})
    model.add_state("SENT", {"sent"})
    model.add_state("FAILED", {"failed"})

    model.add_transition("IDLE", "QUEUED", "enqueue")
    model.add_transition(
        "QUEUED", "SENT", "send_success"
    )
    model.add_transition(
        "QUEUED", "FAILED", "send_failure"
    )
    model.add_transition("FAILED", "QUEUED", "retry")

    model.initial_state = "IDLE"

    return model


# =============================================================
# PRINT KRIPKE
# =============================================================

def print_kripke(
    model: KripkeModel,
    title: str,
):
    print(f"\n===== {title} =====")

    print(f"Initial state: {model.initial_state}")

    print("\nStates:")

    for name, state in model.states.items():

        props = ", ".join(
            sorted(state.propositions)
        )

        print(f"  {name}: {{{props}}}")

    print("\nTransitions:")

    for transition in model.transitions:

        print(
            f"  {transition.source} "
            f"--[{transition.label}]--> "
            f"{transition.target}"
        )

    print("\nValidation:")

    errors = model.validate()

    if errors:

        for error in errors:

            print(f"  [ERROR] {error}")

    else:

        print("  [OK] Kripke model hợp lệ.")
