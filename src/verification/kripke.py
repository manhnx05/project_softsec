from dataclasses import dataclass, field


# =============================================================
# KRIPKE STATE
# =============================================================

@dataclass
class KripkeState:

    name: str

    propositions: set[str] = field(
        default_factory=set
    )


# =============================================================
# KRIPKE MODEL
# =============================================================

@dataclass
class KripkeModel:

    states: dict[str, KripkeState]

    transitions: dict[str, set[str]]

    initial: str

    # =========================================================
    # SUCCESSORS
    # =========================================================

    def successors(
        self,
        state: str
    ) -> set[str]:

        return self.transitions.get(
            state,
            set()
        )

    # =========================================================
    # CHECK STATE
    # =========================================================

    def has_state(
        self,
        state: str
    ) -> bool:

        return state in self.states

    # =========================================================
    # VALIDATE KRIPKE
    # =========================================================

    def validate(self) -> list[str]:

        errors = []

        # Kiểm tra initial state

        if not self.has_state(
            self.initial
        ):

            errors.append(
                f"Initial state "
                f"'{self.initial}' không tồn tại."
            )

        # Kiểm tra transitions

        for source, targets in self.transitions.items():

            if not self.has_state(source):

                errors.append(
                    f"Transition source "
                    f"'{source}' không tồn tại."
                )

            for target in targets:

                if not self.has_state(target):

                    errors.append(
                        f"Transition target "
                        f"'{target}' không tồn tại."
                    )

        return errors


# =============================================================
# AUTHENTICATION KRIPKE
# =============================================================

def build_auth_kripke() -> KripkeModel:

    states = {

        "LOGGED_OUT": KripkeState(
            "LOGGED_OUT",
            {
                "not_authenticated"
            }
        ),

        "LOGIN_FAILED": KripkeState(
            "LOGIN_FAILED",
            {
                "authentication_failed"
            }
        ),

        "LOGGED_IN": KripkeState(
            "LOGGED_IN",
            {
                "authenticated",
                "session_valid"
            }
        ),

        "LOCKED": KripkeState(
            "LOCKED",
            {
                "account_locked"
            }
        )
    }

    transitions = {

        "LOGGED_OUT": {
            "LOGGED_IN",
            "LOGIN_FAILED"
        },

        "LOGIN_FAILED": {
            "LOGGED_IN",
            "LOGIN_FAILED",
            "LOCKED"
        },

        "LOGGED_IN": {
            "LOGGED_OUT"
        },

        "LOCKED": {
            "LOGGED_OUT"
        }
    }

    return KripkeModel(

        states=states,

        transitions=transitions,

        initial="LOGGED_OUT"
    )


# =============================================================
# EMAIL KRIPKE
# =============================================================

def build_email_kripke() -> KripkeModel:

    states = {

        "IDLE": KripkeState(
            "IDLE",
            {
                "not_queued"
            }
        ),

        "QUEUED": KripkeState(
            "QUEUED",
            {
                "queued"
            }
        ),

        "SENT": KripkeState(
            "SENT",
            {
                "sent"
            }
        ),

        "FAILED": KripkeState(
            "FAILED",
            {
                "failed"
            }
        )
    }

    transitions = {

        "IDLE": {
            "QUEUED"
        },

        "QUEUED": {
            "SENT",
            "FAILED"
        },

        "FAILED": {
            "QUEUED"
        },

        "SENT": set()
    }

    return KripkeModel(

        states=states,

        transitions=transitions,

        initial="IDLE"
    )


# =============================================================
# PRINT KRIPKE
# =============================================================

def print_kripke(
    model: KripkeModel,
    title: str
):

    print(
        f"\n===== {title} ====="
    )

    print(
        f"Initial state: "
        f"{model.initial}"
    )

    # ---------------------------------------------------------
    # STATES
    # ---------------------------------------------------------

    print("\nStates:")

    for name, state in model.states.items():

        props = ", ".join(
            sorted(
                state.propositions
            )
        )

        print(
            f"  {name}: "
            f"{{{props}}}"
        )

    # ---------------------------------------------------------
    # TRANSITIONS
    # ---------------------------------------------------------

    print("\nTransitions:")

    for source, targets in model.transitions.items():

        for target in sorted(targets):

            print(
                f"  {source} -> {target}"
            )

    # ---------------------------------------------------------
    # VALIDATION
    # ---------------------------------------------------------

    errors = model.validate()

    print("\nValidation:")

    if errors:

        for error in errors:

            print(
                f"  [ERROR] {error}"
            )

    else:

        print(
            "  [OK] Kripke model hợp lệ."
        )