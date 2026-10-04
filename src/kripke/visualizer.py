import networkx as nx
from pyvis.network import Network

from src.kripke.model import KripkeModel


def create_graph(model: KripkeModel):

    graph = nx.DiGraph()

    for state in model.states.values():

        graph.add_node(
            state.name,
            propositions=", ".join(
                state.propositions
            ),
        )

    for transition in model.transitions:

        graph.add_edge(
            transition.source,
            transition.target,
            label=transition.label,
        )

    return graph


def create_pyvis(
    model: KripkeModel,
    output_file: str = "kripke.html",
):

    net = Network(
        height="600px",
        width="100%",
        directed=True,
    )

    for state in model.states.values():

        net.add_node(
            state.name,
            label=state.name,
            title=", ".join(
                state.propositions
            ),
        )

    for transition in model.transitions:

        net.add_edge(
            transition.source,
            transition.target,
            label=transition.label,
        )

    net.save_graph(output_file)

    return output_file