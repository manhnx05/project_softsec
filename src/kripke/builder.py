"""Build a Kripke Structure K = (S, S_0, R, L) from a FunctionSpec.

The builder maps each YAML-defined state and transition to the formal
model, assigns Atomic Propositions (AP) according to domain-specific
rules, and populates guards from TransitionSpec.guard.
"""

from __future__ import annotations

from src.kripke.model import AtomicProposition, KripkeModel
from src.specification.schemas import FunctionSpec

# =====================================================================
# Predefined Atomic Propositions
# =====================================================================
# These cover the three security domains requested:
#   Authentication, Email Notification, Buffer/Memory Safety.

AP_IS_LOCKED = AtomicProposition("IsLocked", "Account is locked out")
AP_MAX_RETRY_REACHED = AtomicProposition("MaxRetryReached", "Retry limit exceeded")
AP_BUFFER_OVERFLOW_RISK = AtomicProposition("BufferOverflowRisk", "Potential buffer overflow")
AP_AUTHENTICATED = AtomicProposition("Authenticated", "User session is valid")
AP_NOT_AUTHENTICATED = AtomicProposition("NotAuthenticated", "User is not logged in")
AP_AUTH_FAILED = AtomicProposition("AuthFailed", "Login attempt failed")
AP_EMAIL_QUEUED = AtomicProposition("EmailQueued", "Email is in the send queue")
AP_EMAIL_SENT = AtomicProposition("EmailSent", "Email was delivered successfully")
AP_EMAIL_FAILED = AtomicProposition("EmailFailed", "Email delivery failed")
AP_EMAIL_IDLE = AtomicProposition("EmailIdle", "Email not yet queued")

# =====================================================================
# Domain-specific labelling rules:  L(s) -> 2^AP
# =====================================================================
# Maps (function_name.lower(), state_name) -> set of AP.

_LABELLING_RULES: dict[tuple[str, str], set[AtomicProposition]] = {
    # -- Authentication ------------------------------------------------
    ("authentication", "LOGGED_OUT"):    {AP_NOT_AUTHENTICATED},
    ("authentication", "LOGIN_FAILED"):  {AP_AUTH_FAILED, AP_NOT_AUTHENTICATED},
    ("authentication", "LOGGED_IN"):     {AP_AUTHENTICATED},
    ("authentication", "LOCKED"):        {AP_IS_LOCKED, AP_NOT_AUTHENTICATED},

    # -- Email Notification --------------------------------------------
    ("emailnotification", "IDLE"):       {AP_EMAIL_IDLE},
    ("emailnotification", "QUEUED"):     {AP_EMAIL_QUEUED},
    ("emailnotification", "SENT"):       {AP_EMAIL_SENT},
    ("emailnotification", "FAILED"):     {AP_EMAIL_FAILED, AP_MAX_RETRY_REACHED},
}

# =====================================================================
# Guard inference rules
# =====================================================================
# When the YAML spec does not include an explicit guard string, the
# builder infers one from known event names.

_GUARD_RULES: dict[str, str] = {
    "wrong_password":   "attempts < max_attempts",
    "correct_password": "password_valid == true",
    "max_attempts":     "attempts >= max_attempts",
    "logout":           "session_valid == true",
    "reset_lock":       "admin_reset == true",
    "enqueue":          "valid_recipient == true",
    "send_success":     "transport_ok == true",
    "send_failure":     "transport_ok == false",
    "retry":            "retry_count < max_retry",
}


# =====================================================================
# Builder
# =====================================================================

def build_kripke(function: FunctionSpec) -> KripkeModel:
    """Construct a ``KripkeModel`` from a ``FunctionSpec``.

    Returns
    -------
    KripkeModel
        Fully populated model with S, S_0, R, AP, and L(s).
    """
    model = KripkeModel()
    fn_key = function.name.lower()

    # -- Collect all AP relevant to this function ----------------------
    used_aps: set[AtomicProposition] = set()
    for state_spec in function.states:
        aps = _LABELLING_RULES.get((fn_key, state_spec.name), set())
        used_aps.update(aps)

    for ap in used_aps:
        model.register_ap(ap)

    # -- Build S -------------------------------------------------------
    for state_spec in function.states:
        aps = _LABELLING_RULES.get((fn_key, state_spec.name), set())
        legacy_props = {f"state_{state_spec.name.lower()}"}
        model.add_state(
            name=state_spec.name,
            propositions=legacy_props,
            aps=aps,
        )

    # -- S_0 -----------------------------------------------------------
    if function.states:
        model.initial_state = function.states[0].name

    # -- Build R (with guards) ----------------------------------------
    for t in function.transitions:
        guard = t.guard if t.guard else _GUARD_RULES.get(t.event)
        model.add_transition(
            source=t.source,
            target=t.target,
            label=t.event,
            guard=guard,
        )

    return model