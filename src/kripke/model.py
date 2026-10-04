from dataclasses import dataclass, field


@dataclass
class KripkeState:
    name: str
    propositions: set[str] = field(default_factory=set)


@dataclass
class KripkeTransition:
    source: str
    target: str
    label: str


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
    ):
        self.states[name] = KripkeState(
            name=name,
            propositions=propositions or set(),
        )

    def add_transition(
        self,
        source: str,
        target: str,
        label: str,
    ):
        self.transitions.append(
            KripkeTransition(
                source=source,
                target=target,
                label=label,
            )
        )