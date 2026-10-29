"""Bounded model checking for the LMS Kripke structures.

The checker encodes a bounded path of ``bound + 1`` states in Z3 and asks
whether a target state is reachable. A ``SAT`` verdict means the target is
reachable within the bound (a witness path is returned); ``UNSAT`` means it is
not reachable within the bound; ``UNKNOWN`` means Z3 could not decide.
"""

from dataclasses import dataclass, field

import z3

from src.kripke.model import KripkeModel


@dataclass
class BmcResult:
    start: str
    target: str
    bound: int
    status: str
    witness: list[str] = field(default_factory=list)
    detail: str = ""


def check_reachability(
    model: KripkeModel,
    start: str,
    target: str,
    bound: int = 8,
) -> BmcResult:
    """Return whether ``target`` is reachable from ``start`` within ``bound``."""
    if bound < 0:
        raise ValueError("bound must be non-negative")

    states = list(model.states)
    index = {name: position for position, name in enumerate(states)}

    if start not in index:
        return BmcResult(
            start=start,
            target=target,
            bound=bound,
            status="ERROR",
            detail=f"Start state '{start}' does not exist.",
        )
    if target not in index:
        return BmcResult(
            start=start,
            target=target,
            bound=bound,
            status="ERROR",
            detail=f"Target state '{target}' does not exist.",
        )

    edges = [
        (index[transition.source], index[transition.target])
        for transition in model.transitions
        if transition.source in index
        and transition.target in index
    ]

    solver = z3.Solver()
    path = [z3.Int(f"s_{step}") for step in range(bound + 1)]

    for step in range(bound + 1):
        solver.add(path[step] >= 0, path[step] < len(states))
        if step > 0:
            solver.add(
                z3.Or(
                    *[
                        z3.And(path[step - 1] == source, path[step] == sink)
                        for source, sink in edges
                    ]
                )
            )

    solver.add(path[0] == index[start])
    solver.add(
        z3.Or(*[path[step] == index[target] for step in range(bound + 1)])
    )

    result = solver.check()

    if result == z3.sat:
        evaluation = solver.model()
        witness = [
            states[evaluation.eval(path[step]).as_long()]
            for step in range(bound + 1)
        ]
        return BmcResult(
            start=start,
            target=target,
            bound=bound,
            status="SAT",
            witness=witness,
            detail=" -> ".join(witness),
        )

    if result == z3.unsat:
        return BmcResult(
            start=start,
            target=target,
            bound=bound,
            status="UNSAT",
            detail=(
                f"'{target}' is not reachable from '{start}' "
                f"within {bound} steps."
            ),
        )

    return BmcResult(
        start=start,
        target=target,
        bound=bound,
        status="UNKNOWN",
        detail="Z3 could not decide the reachability query.",
    )
