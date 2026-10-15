from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass
class ConstraintResult:
    name: str
    passed: bool
    message: str


@dataclass
class ConstraintRule:
    name: str
    description: str
    check: Callable[[dict[str, Any]], bool]

    def evaluate(self, context: dict[str, Any]) -> ConstraintResult:

        try:
            passed = self.check(context)

            return ConstraintResult(
                name=self.name,
                passed=passed,
                message=(
                    "Constraint satisfied"
                    if passed
                    else "Constraint violated"
                ),
            )

        except (KeyError, TypeError, ValueError) as exc:

            return ConstraintResult(
                name=self.name,
                passed=False,
                message=str(exc),
            )