"""Bounded formal model for the C buffer-copy example."""

from dataclasses import dataclass

BUFFER_CAPACITY = 16
MODEL_STATES = (
    "S0_INPUT",
    "S1_VALIDATE",
    "S2_REJECT",
    "S3_COPY",
    "S4_DONE",
)
MODEL_TRANSITIONS = {
    "S0_INPUT": {"S1_VALIDATE"},
    "S1_VALIDATE": {"S2_REJECT", "S3_COPY"},
    "S2_REJECT": {"S4_DONE"},
    "S3_COPY": {"S4_DONE"},
    "S4_DONE": set(),
}
SAFETY_CONSTRAINTS = (
    (
        "valid_length = (length >= 0 AND length <= source_size "
        "AND length <= destination_capacity)"
    ),
    "NOT valid_length implies transition to S2_REJECT",
    "valid_length implies transition to S3_COPY",
    (
        "copied implies (length >= 0 AND length <= source_size "
        "AND length <= destination_capacity)"
    ),
)


@dataclass(frozen=True)
class ModelEvaluation:
    implementation: str
    length: int
    source_size: int
    destination_capacity: int
    copied: bool
    trace: tuple[str, ...]
    violations: tuple[str, ...]


def evaluate_copy(
    implementation: str,
    length: int,
    source_size: int,
    destination_capacity: int,
) -> ModelEvaluation:
    """Evaluate the guards implemented by the vulnerable or safe C function."""
    if implementation not in {"vulnerable", "safe"}:
        raise ValueError(f"Unknown implementation: {implementation}")
    if source_size < 0 or destination_capacity < 0:
        raise ValueError("Buffer sizes cannot be negative.")

    trace = ["S0_INPUT", "S1_VALIDATE"]
    violations: list[str] = []

    if implementation == "vulnerable":
        rejected = length > destination_capacity
    else:
        rejected = (
            length < 0
            or length > source_size
            or length > destination_capacity
        )

    if rejected:
        trace.extend(("S2_REJECT", "S4_DONE"))
        return ModelEvaluation(
            implementation=implementation,
            length=length,
            source_size=source_size,
            destination_capacity=destination_capacity,
            copied=False,
            trace=tuple(trace),
            violations=(),
        )

    trace.extend(("S3_COPY", "S4_DONE"))
    if length < 0:
        violations.append("negative length is converted to an unsigned size")
    if length > source_size:
        violations.append("copy length exceeds source buffer size")
    if length > destination_capacity:
        violations.append("copy length exceeds destination buffer capacity")

    return ModelEvaluation(
        implementation=implementation,
        length=length,
        source_size=source_size,
        destination_capacity=destination_capacity,
        copied=True,
        trace=tuple(trace),
        violations=tuple(violations),
    )


def find_bounded_counterexample(
    implementation: str,
    lengths: range,
    sizes: tuple[int, ...] = (0, 1, 8, BUFFER_CAPACITY),
) -> ModelEvaluation | None:
    """Find a violation over the explicit finite input domain supplied."""
    for source_size in sizes:
        for destination_capacity in sizes:
            for length in lengths:
                evaluation = evaluate_copy(
                    implementation,
                    length,
                    source_size,
                    destination_capacity,
                )
                if evaluation.violations:
                    return evaluation
    return None


def validate_model() -> list[str]:
    errors = []
    if MODEL_STATES[0] not in MODEL_TRANSITIONS:
        errors.append("The initial state is missing from the transition graph.")

    for source, targets in MODEL_TRANSITIONS.items():
        if source not in MODEL_STATES:
            errors.append(f"Unknown transition source: {source}")
        for target in targets:
            if target not in MODEL_STATES:
                errors.append(f"Unknown transition target: {target}")

    if MODEL_TRANSITIONS["S1_VALIDATE"] != {"S2_REJECT", "S3_COPY"}:
        errors.append("Validation must lead to rejection or copying.")
    return errors
