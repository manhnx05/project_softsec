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