from dataclasses import dataclass, field


@dataclass
class KripkeState:
    name: str
    propositions: set[str] = field(default_factory=set)
    description: str = ""


@dataclass
class KripkeTransition:
    source: str
    target: str
    label: str
    guard: str | None = None


@dataclass
class KripkeModel:

    states: dict[str, KripkeState] = field(
        default_factory=dict
    )

    transitions: list[KripkeTransition] = field(
        default_factory=list
    )

    initial_state: str | None = None

    def add_state(
        self,
        name: str,
        propositions: set[str] | None = None,
        description: str = "",
    ):
        self.states[name] = KripkeState(
            name=name,
            description=description,
            propositions=propositions or set(),
        )

    def add_transition(
        self,
        source: str,
        target: str,
        label: str,
        guard: str | None = None,
    ):
        self.transitions.append(
            KripkeTransition(
                source=source,
                target=target,
                label=label,
                guard=guard,
            )
        )

    def successors(self, name: str) -> set[str]:
        """Return the set of states reachable from ``name`` in one step."""
        return {
            transition.target
            for transition in self.transitions
            if transition.source == name
        }

    def validate(self) -> list[str]:
        """Return structural errors; an empty list means the model is valid."""
        errors: list[str] = []

        if not self.states:
            errors.append("The model has no states.")

        if self.initial_state is None:
            errors.append("The model has no initial state.")
        elif self.initial_state not in self.states:
            errors.append(
                f"Initial state '{self.initial_state}' is not a declared state."
            )

        for transition in self.transitions:
            if transition.source not in self.states:
                errors.append(
                    f"Transition source '{transition.source}' is not a "
                    "declared state."
                )
            if transition.target not in self.states:
                errors.append(
                    f"Transition target '{transition.target}' is not a "
                    "declared state."
                )

        return errors