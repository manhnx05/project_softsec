from dataclasses import dataclass
from typing import Callable


@dataclass
class ConstraintResult:
    name: str
    passed: bool
    message: str


@dataclass
class ConstraintRule:
    name: str
    description: str
    check: Callable[[dict], bool]

    def evaluate(self, context: dict) -> ConstraintResult:

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

        except Exception as exc:

            return ConstraintResult(
                name=self.name,
                passed=False,
                message=str(exc),
            )