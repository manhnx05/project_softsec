"""Formal Kripke Structure  K = (S, S_0, R, L).

Mathematical definition
-----------------------
    S   -- finite set of states
    S_0 -- initial state  (S_0 in S)
    R   -- transition relation  R <= S x S  (with guards / event labels)
    AP  -- finite set of Atomic Propositions
    L   -- labelling function   L : S -> 2^AP
"""

from __future__ import annotations

from dataclasses import dataclass, field


# =====================================================================
# Atomic Proposition
# =====================================================================

@dataclass(frozen=True)
class AtomicProposition:
    """A single atomic proposition p in AP.

    Attributes
    ----------
    name:
        Machine-readable identifier, e.g. ``"IsLocked"``.
    description:
        Human-readable explanation shown on the UI.
    """
    name: str
    description: str = ""

    def __str__(self) -> str:
        return self.name


# =====================================================================
# Kripke State  (a member of S with its labelling L(s))
# =====================================================================

@dataclass
class KripkeState:
    """A state s in S together with L(s) <= AP.

    Attributes
    ----------
    name:
        Unique state identifier (e.g. ``"LOGGED_OUT"``).
    propositions:
        Legacy plain-string proposition set (kept for backward
        compatibility with ``src/verification/kripke.py``).
    atomic_propositions:
        Rich AP objects assigned via the labelling function L(s).
    """
    name: str
    propositions: set[str] = field(default_factory=set)
    atomic_propositions: set[AtomicProposition] = field(default_factory=set)

    # convenience -------------------------------------------------------

    @property
    def ap_names(self) -> set[str]:
        """Return ``{p.name for p in L(s)}``."""
        return {ap.name for ap in self.atomic_propositions}

    def label_display(self) -> str:
        """Formatted label text for graph node rendering.

        Shows the state name on the first line, followed by each
        atomic proposition that holds in this state.
        """
        if not self.atomic_propositions:
            # fall back to legacy propositions
            if self.propositions:
                props = ", ".join(sorted(self.propositions))
                return f"{self.name}\n{{{props}}}"
            return self.name

        props = ", ".join(sorted(ap.name for ap in self.atomic_propositions))
        return f"{self.name}\n{{{props}}}"


# =====================================================================
# Kripke Transition  (an element of R with an optional guard)
# =====================================================================

@dataclass
class KripkeTransition:
    """An element (s, s') in R with an event label and optional guard.

    Attributes
    ----------
    source:
        Source state name.
    target:
        Target state name.
    label:
        Event that triggers the transition (e.g. ``"wrong_password"``).
    guard:
        Optional boolean guard expression (e.g. ``"attempts < max"``).
    """
    source: str
    target: str
    label: str
    guard: str | None = None

    def edge_display(self) -> str:
        """Formatted edge label for graph rendering."""
        if self.guard:
            return f"{self.label}\n[{self.guard}]"
        return self.label


# =====================================================================
# Kripke Model  K = (S, S_0, R, L)
# =====================================================================

@dataclass
class KripkeModel:
    """Complete Kripke Structure ``K = (S, S_0, R, L)``.

    Attributes
    ----------
    states:
        ``S`` -- mapping from state name to :class:`KripkeState`.
    transitions:
        ``R`` -- list of :class:`KripkeTransition` (labelled edges).
    initial_state:
        ``S_0`` -- name of the initial state.
    atomic_propositions:
        ``AP`` -- the full set of propositions used in this model.
    """
    states: dict[str, KripkeState] = field(default_factory=dict)
    transitions: list[KripkeTransition] = field(default_factory=list)
    initial_state: str | None = None
    atomic_propositions: set[AtomicProposition] = field(default_factory=set)

    # -- mutators -------------------------------------------------------

    def register_ap(self, ap: AtomicProposition) -> AtomicProposition:
        """Register an atomic proposition in AP and return it."""
        self.atomic_propositions.add(ap)
        return ap

    def add_state(
        self,
        name: str,
        propositions: set[str] | None = None,
        aps: set[AtomicProposition] | None = None,
    ) -> KripkeState:
        """Create and insert a state into S.

        Parameters
        ----------
        name:
            State identifier.
        propositions:
            Legacy plain-string propositions (backward compatible).
        aps:
            Rich :class:`AtomicProposition` objects for L(s).
        """
        state = KripkeState(
            name=name,
            propositions=propositions or set(),
            atomic_propositions=aps or set(),
        )
        self.states[name] = state
        return state

    def add_transition(
        self,
        source: str,
        target: str,
        label: str,
        guard: str | None = None,
    ) -> KripkeTransition:
        """Add an element to R."""
        transition = KripkeTransition(
            source=source,
            target=target,
            label=label,
            guard=guard,
        )
        self.transitions.append(transition)
        return transition

    # -- queries --------------------------------------------------------

    def successors(self, state: str) -> set[str]:
        """Return the set of states reachable in one step from *state*."""
        return {t.target for t in self.transitions if t.source == state}

    def has_state(self, state: str) -> bool:
        return state in self.states

    def labelling(self, state: str) -> set[AtomicProposition]:
        """Return ``L(s)`` -- the set of AP that hold in *state*."""
        if state in self.states:
            return self.states[state].atomic_propositions
        return set()

    # -- validation -----------------------------------------------------

    def validate(self) -> list[str]:
        """Check structural integrity of the model.

        Returns a list of error strings (empty means valid).
        """
        errors: list[str] = []

        if self.initial_state is not None and not self.has_state(self.initial_state):
            errors.append(
                f"Initial state '{self.initial_state}' is not in S."
            )

        for t in self.transitions:
            if not self.has_state(t.source):
                errors.append(
                    f"Transition source '{t.source}' is not in S."
                )
            if not self.has_state(t.target):
                errors.append(
                    f"Transition target '{t.target}' is not in S."
                )

        return errors

    # -- summary --------------------------------------------------------

    def summary(self) -> dict[str, object]:
        """Return a dict summary suitable for display in Streamlit."""
        return {
            "|S|": len(self.states),
            "|R|": len(self.transitions),
            "|AP|": len(self.atomic_propositions),
            "S_0": self.initial_state,
            "AP": ", ".join(sorted(ap.name for ap in self.atomic_propositions)),
        }