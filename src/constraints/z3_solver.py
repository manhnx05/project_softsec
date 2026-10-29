from z3 import (
    Bool,
    Int,
    Solver,
    sat,
    unsat,
)


def _status(solver: Solver) -> str:
    result = solver.check()
    if result == sat:
        return "SAT"
    if result == unsat:
        return "UNSAT"
    return "UNKNOWN"


class Z3ConstraintEngine:

    def __init__(self):
        self.solver = Solver()

    def add_authentication_constraints(
        self,
        max_attempts: int,
        min_password_length: int,
    ):
        attempts = Int("attempts")
        password_length = Int("password_length")
        login_allowed = Bool("login_allowed")
        locked = Bool("locked")

        self.solver.add(attempts >= 0)
        self.solver.add(attempts <= max_attempts)

        self.solver.add(
            password_length >= min_password_length
        )

        self.solver.add(
            locked == True,
            login_allowed == False
        )

    def check(self) -> bool:
        return self.solver.check() == sat

    def status(self) -> str:
        """Return SAT, UNSAT, or UNKNOWN for the accumulated constraints."""
        return _status(self.solver)

    def model(self):
        if self.solver.check() == sat:
            return self.solver.model()

        return None

    def reset(self):
        self.solver.reset()


def check_locked_login_safety(
    max_attempts: int = 3,
    min_password_length: int = 8,
) -> str:
    """Return SAT/UNSAT for "a locked account may login".

    The engine asserts the policy ``locked -> not login_allowed`` and then asks
    whether a model exists where ``locked`` and ``login_allowed`` are both true.
    ``UNSAT`` proves the policy forbids it; ``SAT`` would be a violation.
    """
    attempts = Int("attempts")
    password_length = Int("password_length")
    login_allowed = Bool("login_allowed")
    locked = Bool("locked")

    solver = Solver()
    solver.add(attempts >= 0, attempts <= max_attempts)
    solver.add(password_length >= min_password_length)
    solver.add(locked == True, login_allowed == False)
    solver.add(locked == True, login_allowed == True)

    return _status(solver)
