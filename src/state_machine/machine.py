from src.state_machine.state import State
from src.state_machine.transition import Transition


class StateMachine:

    def __init__(
        self,
        states: list[State],
        transitions: list[Transition],
        initial_state: str,
    ):
        self.states = {
            state.name: state
            for state in states
        }

        self.transitions = transitions
        self.initial_state = initial_state
        self.current_state = initial_state

    def reset(self):
        self.current_state = self.initial_state

    def available_transitions(self) -> list[Transition]:
        return [
            transition
            for transition in self.transitions
            if transition.source == self.current_state
        ]

    def transition(self, event: str) -> bool:

        for transition in self.available_transitions():

            if transition.event == event:

                self.current_state = transition.target

                return True

        return False

    def can_transition(self, event: str) -> bool:
        return any(
            transition.event == event
            for transition in self.available_transitions()
        )

    def get_state(self) -> State:
        return self.states[self.current_state]