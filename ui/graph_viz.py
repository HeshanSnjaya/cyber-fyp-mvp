"""Interactive attack-graph rendering for the Streamlit UI.

Builds a pyvis network from the analysis result, colour-coded by resource type,
with edges that lie on a discovered attack path highlighted in red. Returns raw
HTML that the app embeds via ``streamlit.components.v1.html``.
"""

from __future__ import annotations

from core import graph_engine

# Colour palette per node type.
_NODE_STYLE = {
    "internet": {"color": "#8b5cf6", "shape": "star", "size": 34},
    "ec2": {"color": "#3b82f6", "shape": "box", "size": 26},
    "iam_role": {"color": "#f59e0b", "shape": "diamond", "size": 26},
    "s3": {"color": "#10b981", "shape": "database", "size": 26},
}
_SENSITIVE_COLOR = "#ef4444"
_ATTACK_EDGE_COLOR = "#ef4444"
_NORMAL_EDGE_COLOR = "#94a3b8"


def render_attack_graph(result, height="600px"):
    """Return standalone HTML for the interactive attack graph.

    Falls back to ``None`` if pyvis is unavailable so the caller can degrade
    gracefully to a static table.
    """
    try:
        from pyvis.network import Network
    except Exception:
        return None

    resources = result["resources"]
    graph = graph_engine.build_graph(resources)

    # Collect the set of directed edges that appear on any attack path.
    attack_edges = set()
    attack_nodes = set()
    for finding in result["findings"]:
        path = finding["path"]
        attack_nodes.update(path)
        for i in range(len(path) - 1):
            attack_edges.add((path[i], path[i + 1]))

    net = Network(
        height=height,
        width="100%",
        directed=True,
        bgcolor="#0e1117",
        font_color="#e2e8f0",
        notebook=False,
    )
    net.barnes_hut(gravity=-8000, spring_length=160, spring_strength=0.02)

    for node, data in graph.nodes(data=True):
        ntype = data.get("type", "unknown")
        style = _NODE_STYLE.get(ntype, {"color": "#64748b", "shape": "dot", "size": 22})
        color = style["color"]
        if ntype == "s3" and data.get("sensitive"):
            color = _SENSITIVE_COLOR
        border = "#f8fafc" if node in attack_nodes else color
        net.add_node(
            node,
            label=node,
            title=_node_tooltip(node, data),
            color={"background": color, "border": border},
            shape=style["shape"],
            size=style["size"] + (8 if node in attack_nodes else 0),
            borderWidth=3 if node in attack_nodes else 1,
        )

    for src, dst, data in graph.edges(data=True):
        on_path = (src, dst) in attack_edges
        net.add_edge(
            src,
            dst,
            title=data.get("relation", ""),
            label=data.get("relation", "") if on_path else "",
            color=_ATTACK_EDGE_COLOR if on_path else _NORMAL_EDGE_COLOR,
            width=4 if on_path else 1,
            arrows="to",
        )

    net.set_options(
        """
        {
          "interaction": {"hover": true, "tooltipDelay": 80},
          "physics": {"stabilization": {"iterations": 150}},
          "edges": {"smooth": {"type": "dynamic"}}
        }
        """
    )

    try:
        return net.generate_html(notebook=False)
    except TypeError:
        # Older pyvis signatures.
        return net.generate_html()


def _node_tooltip(node, data):
    lines = [f"{node}", f"type: {data.get('type')}"]
    for key in ("description", "region", "public", "public_ip", "sensitive",
                "encrypted", "admin", "instance_id"):
        if key in data and data[key] not in (None, ""):
            lines.append(f"{key}: {data[key]}")
    return "\n".join(str(l) for l in lines)


def legend_items():
    """Return (label, color) pairs for a UI legend."""
    return [
        ("Internet", _NODE_STYLE["internet"]["color"]),
        ("EC2 instance", _NODE_STYLE["ec2"]["color"]),
        ("IAM role", _NODE_STYLE["iam_role"]["color"]),
        ("S3 bucket", _NODE_STYLE["s3"]["color"]),
        ("Sensitive S3 / attack edge", _SENSITIVE_COLOR),
    ]
