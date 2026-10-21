"""Verification-layer Kripke builders for Authentication and Email.

These functions build *hardcoded* Kripke structures that match the
project's security specs, independent of YAML.  They are used by
``tests/test_lms.py`` for direct model validation.

Since this module now re-exports the canonical model from
``src.kripke.model``, both ``src/kripke/`` and this module share the
same ``KripkeModel``, ``KripkeState``, and ``AtomicProposition`` classes.
"""

from src.kripke.model import (
    AtomicProposition,
    KripkeModel,
    KripkeState,
)

# =====================================================================
# Predefined AP for the verification layer
# =====================================================================

AP_NOT_AUTHENTICATED = AtomicProposition("NotAuthenticated", "User is not logged in")
AP_AUTH_FAILED       = AtomicProposition("AuthFailed", "Login attempt failed")
AP_AUTHENTICATED     = AtomicProposition("Authenticated", "User session is valid")
AP_IS_LOCKED         = AtomicProposition("IsLocked", "Account is locked out")
AP_EMAIL_IDLE        = AtomicProposition("EmailIdle", "Email not yet queued")
AP_EMAIL_QUEUED      = AtomicProposition("EmailQueued", "Email is in the send queue")
AP_EMAIL_SENT        = AtomicProposition("EmailSent", "Email was delivered successfully")
AP_EMAIL_FAILED      = AtomicProposition("EmailFailed", "Email delivery failed")
AP_MAX_RETRY         = AtomicProposition("MaxRetryReached", "Retry limit exceeded")

# =====================================================================
# AUTHENTICATION KRIPKE
# =====================================================================

def build_auth_kripke() -> KripkeModel:
    """Build the Authentication Kripke structure.

    States: LOGGED_OUT, LOGIN_FAILED, LOGGED_IN, LOCKED
    """
    model = KripkeModel()
    model.initial_state = "LOGGED_OUT"

    # Register AP
    for ap in (AP_NOT_AUTHENTICATED, AP_AUTH_FAILED, AP_AUTHENTICATED, AP_IS_LOCKED):
        model.register_ap(ap)

    # S -- states with L(s)
    model.add_state("LOGGED_OUT",   propositions={"not_authenticated"},
                     aps={AP_NOT_AUTHENTICATED})
    model.add_state("LOGIN_FAILED", propositions={"authentication_failed"},
                     aps={AP_AUTH_FAILED, AP_NOT_AUTHENTICATED})
    model.add_state("LOGGED_IN",    propositions={"authenticated", "session_valid"},
                     aps={AP_AUTHENTICATED})
    model.add_state("LOCKED",       propositions={"account_locked"},
                     aps={AP_IS_LOCKED, AP_NOT_AUTHENTICATED})

    # R -- transitions with guards
    model.add_transition("LOGGED_OUT",   "LOGGED_IN",    "correct_password",
                          guard="password_valid == true")
    model.add_transition("LOGGED_OUT",   "LOGIN_FAILED", "wrong_password",
                          guard="attempts < max_attempts")
    model.add_transition("LOGIN_FAILED", "LOGIN_FAILED", "wrong_password",
                          guard="attempts < max_attempts")
    model.add_transition("LOGIN_FAILED", "LOGGED_IN",    "correct_password",
                          guard="password_valid == true")
    model.add_transition("LOGIN_FAILED", "LOCKED",       "max_attempts",
                          guard="attempts >= max_attempts")
    model.add_transition("LOGGED_IN",    "LOGGED_OUT",   "logout",
                          guard="session_valid == true")
    model.add_transition("LOCKED",       "LOGGED_OUT",   "reset_lock",
                          guard="admin_reset == true")

    return model


# =====================================================================
# EMAIL KRIPKE
# =====================================================================

def build_email_kripke() -> KripkeModel:
    """Build the Email Notification Kripke structure.

    States: IDLE, QUEUED, SENT, FAILED
    """
    model = KripkeModel()
    model.initial_state = "IDLE"

    # Register AP
    for ap in (AP_EMAIL_IDLE, AP_EMAIL_QUEUED, AP_EMAIL_SENT,
               AP_EMAIL_FAILED, AP_MAX_RETRY):
        model.register_ap(ap)

    # S -- states with L(s)
    model.add_state("IDLE",   propositions={"not_queued"},
                     aps={AP_EMAIL_IDLE})
    model.add_state("QUEUED", propositions={"queued"},
                     aps={AP_EMAIL_QUEUED})
    model.add_state("SENT",   propositions={"sent"},
                     aps={AP_EMAIL_SENT})
    model.add_state("FAILED", propositions={"failed"},
                     aps={AP_EMAIL_FAILED, AP_MAX_RETRY})

    # R -- transitions with guards
    model.add_transition("IDLE",   "QUEUED",  "enqueue",
                          guard="valid_recipient == true")
    model.add_transition("QUEUED", "SENT",    "send_success",
                          guard="transport_ok == true")
    model.add_transition("QUEUED", "FAILED",  "send_failure",
                          guard="transport_ok == false")
    model.add_transition("FAILED", "QUEUED",  "retry",
                          guard="retry_count < max_retry")

    return model


# =====================================================================
# PRINT KRIPKE
# =====================================================================

def print_kripke(
    model: KripkeModel,
    title: str,
) -> None:
    """Pretty-print a Kripke structure to stdout."""

    print(f"\n===== {title} =====")
    print(f"S_0 = {model.initial_state}")

    # AP
    if model.atomic_propositions:
        print(f"AP  = {{{', '.join(sorted(ap.name for ap in model.atomic_propositions))}}}")

    # States with L(s)
    print("\nS (states) with L(s):")
    for name, state in model.states.items():
        if state.atomic_propositions:
            ap_str = ", ".join(sorted(ap.name for ap in state.atomic_propositions))
        else:
            ap_str = ", ".join(sorted(state.propositions))
        print(f"  {name}: {{{ap_str}}}")

    # Transitions
    print("\nR (transitions):")
    for t in model.transitions:
        guard_str = f" [{t.guard}]" if t.guard else ""
        print(f"  {t.source} --({t.label}){guard_str}--> {t.target}")

    # Validation
    errors = model.validate()
    print("\nValidation:")
    if errors:
        for error in errors:
            print(f"  [ERROR] {error}")
    else:
        print("  [OK] Kripke model is valid.")