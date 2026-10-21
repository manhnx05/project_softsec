"""SMT Constraint Checking Engine powered by Z3.

Formally distinguishes SMT Checking from Static Analysis, BMC, and Sanitizers:
- SMT Checking transforms logic formulas, invariants, and guard conditions into
  first-order logic theories (Linear Integer Arithmetic, Bit-Vectors, Booleans).
- If SAT: Z3 finds a concrete Counterexample (Model) satisfying the conditions.
- If UNSAT: Z3 produces an Unsat Core (minimal conflicting constraints) proving
  that no violation exists or identifying why constraints conflict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from z3 import (
    And,
    Bool,
    BoolRef,
    CheckSatResult,
    ExprRef,
    Int,
    ModelRef,
    Not,
    Or,
    Solver,
    sat,
    unknown,
    unsat,
)


@dataclass
class SMTResult:
    """Structured result of an SMT satisfiability or invariant query."""

    status: str  # "SAT" | "UNSAT" | "UNKNOWN"
    is_sat: bool
    model: dict[str, Any] = field(default_factory=dict)
    unsat_core: list[str] = field(default_factory=list)
    explanation: str = ""

    def summary(self) -> str:
        if self.status == "SAT":
            model_str = ", ".join(f"{k}={v}" for k, v in sorted(self.model.items()))
            return f"SAT: Counterexample found -> {{{model_str}}}"
        if self.status == "UNSAT":
            core_str = ", ".join(self.unsat_core) if self.unsat_core else "No tracked core"
            return f"UNSAT: Proved infeasible. Conflicting Core: [{core_str}]"
        return f"UNKNOWN: {self.explanation}"


class Z3ConstraintEngine:
    """High-level SMT solver engine wrapping Z3 with assert-and-track capabilities.

    Features
    --------
    * Tracked Assertions: Every constraint can be tagged with a label to allow
      Z3 to compute the exact ``unsat_core()`` on contradictory formulas.
    * Invariant Verification: Proves Invariants by checking whether
      ``Assumptions AND NOT(Invariant)`` is UNSAT.
    * Counterexample Extraction: Directly extracts variable assignments as Python
      primitives when a property is violated (SAT).
    """

    def __init__(self) -> None:
        self.solver = Solver()
        self.solver.set(unsat_core=True)
        self._tracked_constraints: dict[str, BoolRef] = {}

    # ------------------------------------------------------------------
    # Core SMT Operations
    # ------------------------------------------------------------------

    def add_constraint(self, formula: BoolRef, name: str | None = None) -> None:
        """Add a constraint to the solver.

        If a ``name`` is provided, the constraint is tracked via
        ``assert_and_track`` to allow extracting it in ``unsat_core()``.
        """
        if name:
            tracker = Bool(name)
            self._tracked_constraints[name] = tracker
            self.solver.assert_and_track(formula, tracker)
        else:
            self.solver.add(formula)

    def check(self) -> bool:
        """Return True if the assertions are satisfiable (SAT), False otherwise."""
        return self.solver.check() == sat

    def check_satisfiability(self) -> SMTResult:
        """Run satisfiability check and return an enriched SMTResult.

        * If SAT: extracts Model (counterexample assignment).
        * If UNSAT: extracts Unsat Core (conflicting constraints).
        """
        raw_result: CheckSatResult = self.solver.check()

        if raw_result == sat:
            m = self.solver.model()
            model_dict = self._model_to_dict(m)
            return SMTResult(
                status="SAT",
                is_sat=True,
                model=model_dict,
                explanation="Formulas are satisfiable. A concrete satisfying model exists.",
            )
        elif raw_result == unsat:
            core = [str(clause) for clause in self.solver.unsat_core()]
            return SMTResult(
                status="UNSAT",
                is_sat=False,
                unsat_core=core,
                explanation="Formulas are contradictory (unsatisfiable). Proof demonstrated by unsat core.",
            )
        else:
            return SMTResult(
                status="UNKNOWN",
                is_sat=False,
                explanation=self.solver.reason_unknown() or "Solver returned unknown.",
            )

    def model(self) -> ModelRef | None:
        """Backward-compatible model getter returning Z3's ModelRef."""
        if self.solver.check() == sat:
            return self.solver.model()
        return None

    def get_model_dict(self) -> dict[str, Any]:
        """Return the current model as a clean Python dictionary."""
        m = self.model()
        return self._model_to_dict(m) if m else {}

    def get_unsat_core(self) -> list[str]:
        """Return the list of tracked constraint names that caused UNSAT."""
        if self.solver.check() == unsat:
            return [str(clause) for clause in self.solver.unsat_core()]
        return []

    def reset(self) -> None:
        """Clear all assertions, trackers, and solver state."""
        self.solver.reset()
        self.solver.set(unsat_core=True)
        self._tracked_constraints.clear()

    # ------------------------------------------------------------------
    # Invariant Verification (Assumptions AND NOT Invariant -> UNSAT)
    # ------------------------------------------------------------------

    def verify_invariant(
        self,
        assumptions: list[tuple[str, BoolRef]],
        invariant: tuple[str, BoolRef],
    ) -> SMTResult:
        """Mathematically verify whether an invariant holds under given assumptions.

        Method
        ------
        To prove that ``Assumptions => Invariant`` is valid:
        We test whether ``Assumptions AND NOT(Invariant)`` is UNSAT.
        - If UNSAT: The invariant strictly holds under all reachable domains.
        - If SAT: The invariant is violated, and the model is a Counterexample.
        """
        self.reset()
        for name, formula in assumptions:
            self.add_constraint(formula, name=name)

        inv_name, inv_formula = invariant
        # Add negation of invariant to search for violation
        violation_tracker_name = f"violation_of_{inv_name}"
        self.add_constraint(Not(inv_formula), name=violation_tracker_name)

        result = self.check_satisfiability()
        if result.status == "UNSAT":
            result.explanation = (
                f"PROVED: Invariant '{inv_name}' holds universally under the given assumptions. "
                "No counterexample exists."
            )
        elif result.status == "SAT":
            result.explanation = (
                f"VIOLATION: Invariant '{inv_name}' can be violated! "
                "The extracted model represents the counterexample."
            )
        return result

    # ------------------------------------------------------------------
    # Domain-Specific Constraint Builders (Backward-Compatible)
    # ------------------------------------------------------------------

    def add_authentication_constraints(
        self,
        max_attempts: int,
        min_password_length: int,
    ) -> None:
        """Build formal constraints for the authentication module."""
        attempts = Int("attempts")
        password_length = Int("password_length")
        login_allowed = Bool("login_allowed")
        locked = Bool("locked")

        self.add_constraint(attempts >= 0, name="attempts_non_negative")
        self.add_constraint(attempts <= max_attempts, name="attempts_within_bound")
        self.add_constraint(password_length >= min_password_length, name="password_min_length")
        self.add_constraint(locked == True, name="account_is_locked")
        self.add_constraint(login_allowed == False, name="locked_implies_no_login")

    def add_email_notification_constraints(
        self,
        max_retry: int,
    ) -> None:
        """Build formal constraints for email notification module."""
        retry_count = Int("retry_count")
        sent = Bool("sent")
        queued = Bool("queued")
        failed = Bool("failed")

        self.add_constraint(retry_count >= 0, name="retry_non_negative")
        self.add_constraint(retry_count <= max_retry, name="retry_within_limit")
        # Queued before sent: if sent, must have been queued
        self.add_constraint(Or(Not(sent), queued), name="queued_before_sent")
        self.add_constraint(failed == (retry_count >= max_retry), name="max_retry_implies_failed")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _model_to_dict(model: ModelRef | None) -> dict[str, Any]:
        if model is None:
            return {}
        result: dict[str, Any] = {}
        for decl in model.decls():
            name = decl.name()
            val = model[decl]
            try:
                # Try integer evaluation
                result[name] = val.as_long()
            except (AttributeError, ValueError):
                val_str = str(val)
                if val_str == "True":
                    result[name] = True
                elif val_str == "False":
                    result[name] = False
                else:
                    result[name] = val_str
        return result