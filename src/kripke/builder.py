from src.kripke.model import KripkeModel
from src.specification.schemas import FunctionSpec


def build_kripke(function: FunctionSpec) -> KripkeModel:

    model = KripkeModel()

    for state in function.states:

        propositions = {
            f"state_{state.name.lower()}"
        }

        model.add_state(
            name=state.name,
            propositions=propositions,
        )

    if function.states:
        model.initial_state = function.states[0].name

    for transition in function.transitions:

        model.add_transition(
            source=transition.source,
            target=transition.target,
            label=transition.event,
        )

    return model