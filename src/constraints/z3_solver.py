from z3 import (
    Bool,
    Int,
    Solver,
    sat,
)


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

    def model(self):
        if self.solver.check() == sat:
            return self.solver.model()

        return None

    def reset(self):
        self.solver.reset()