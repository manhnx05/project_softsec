"""Kripke Structure visualizer -- renders K = (S, S_0, R, L) as graphs.

Provides:
  * ``create_graph``  -- builds a NetworkX DiGraph
  * ``create_pyvis``  -- builds an interactive PyVis HTML graph
  * ``render_graphviz_kripke`` -- builds a Graphviz DOT string for Streamlit

All renderers display L(s) inside each node and guards on each edge.
"""

from __future__ import annotations

import networkx as nx
from pyvis.network import Network

from src.kripke.model import KripkeModel


# -- Colour palette ----------------------------------------------------

_COLOUR_INITIAL = "#A3D9A5"       # green for S_0
_COLOUR_DEFAULT = "#EAF2FF"       # light blue
_COLOUR_LOCKED  = "#F8A5A5"       # red for locked / failure
_COLOUR_SUCCESS = "#A5D8F8"       # blue for success
_EDGE_COLOUR    = "#2F6B9F"
_EDGE_FONT      = "#1F2937"

_STATE_COLOURS: dict[str, str] = {
    "LOCKED":       _COLOUR_LOCKED,
    "FAILED":       _COLOUR_LOCKED,
    "LOGIN_FAILED": "#FFD6A5",     # orange
    "LOGGED_IN":    _COLOUR_SUCCESS,
    "SENT":         _COLOUR_SUCCESS,
}


def _node_colour(state_name: str, is_initial: bool) -> str:
    if is_initial:
        return _COLOUR_INITIAL
    return _STATE_COLOURS.get(state_name, _COLOUR_DEFAULT)


# =====================================================================
# NetworkX graph
# =====================================================================

def create_graph(model: KripkeModel) -> nx.DiGraph:
    """Return a ``networkx.DiGraph`` with AP labels and guards."""
    graph = nx.DiGraph()

    for state in model.states.values():
        graph.add_node(
            state.name,
            label=state.label_display(),
            propositions=", ".join(sorted(state.ap_names)) or "-",
        )

    for t in model.transitions:
        graph.add_edge(
            t.source,
            t.target,
            label=t.edge_display(),
            event=t.label,
            guard=t.guard or "",
        )

    return graph


# =====================================================================
# PyVis interactive HTML graph
# =====================================================================

def create_pyvis(
    model: KripkeModel,
    output_file: str = "kripke.html",
) -> str:
    """Generate an interactive PyVis HTML graph and save it.

    Nodes display ``L(s)`` (atomic propositions) in their tooltip.
    Edges display ``event [guard]`` as the label.
    """
    net = Network(
        height="600px",
        width="100%",
        directed=True,
    )

    for state in model.states.values():
        is_initial = (state.name == model.initial_state)

        # Tooltip shows the full L(s) details
        if state.atomic_propositions:
            tooltip_lines = [f"State: {state.name}"]
            tooltip_lines.append("L(s) = {" + ", ".join(
                sorted(ap.name for ap in state.atomic_propositions)
            ) + "}")
            for ap in sorted(state.atomic_propositions, key=lambda a: a.name):
                if ap.description:
                    tooltip_lines.append(f"  {ap.name}: {ap.description}")
            tooltip = "\n".join(tooltip_lines)
        else:
            tooltip = state.name

        net.add_node(
            state.name,
            label=state.label_display(),
            title=tooltip,
            color=_node_colour(state.name, is_initial),
            shape="box" if is_initial else "ellipse",
        )

    for t in model.transitions:
        net.add_edge(
            t.source,
            t.target,
            label=t.edge_display(),
            title=f"Guard: {t.guard}" if t.guard else t.label,
        )

    net.save_graph(output_file)
    return output_file


# =====================================================================
# Graphviz DOT string  (used by st.graphviz_chart)
# =====================================================================

def render_graphviz_kripke(model: KripkeModel) -> str:
    """Return a Graphviz DOT string rendering K = (S, S_0, R, L).

    * Each node shows the state name and ``L(s)`` on a second line.
    * Each edge shows the event and ``[guard]`` if present.
    * The initial state S_0 is drawn with a double circle.
    """
    lines = [
        "digraph kripke {",
        "  rankdir=LR;",
        '  node [style=filled, fontname="Helvetica"];',
        f'  edge [color="{_EDGE_COLOUR}", fontcolor="{_EDGE_FONT}", '
        f'fontname="Helvetica", fontsize=10];',
    ]

    for state in model.states.values():
        is_initial = (state.name == model.initial_state)
        colour = _node_colour(state.name, is_initial)
        shape = "doublecircle" if is_initial else "ellipse"

        # Build label with L(s)
        if state.atomic_propositions:
            ap_str = ", ".join(sorted(ap.name for ap in state.atomic_propositions))
            node_label = f"{state.name}\\n{{{ap_str}}}"
        elif state.propositions:
            node_label = f"{state.name}\\n{{{', '.join(sorted(state.propositions))}}}"
        else:
            node_label = state.name

        lines.append(
            f'  "{state.name}" [label="{node_label}", '
            f'shape={shape}, fillcolor="{colour}"];'
        )

    for t in model.transitions:
        edge_label = t.label
        if t.guard:
            edge_label += f"\\n[{t.guard}]"
        lines.append(f'  "{t.source}" -> "{t.target}" [label="{edge_label}"];')

    lines.append("}")
    return "\n".join(lines)