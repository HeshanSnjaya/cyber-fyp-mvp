"""Static attack-graph rendering for the Streamlit UI.

Produces a **static, layered diagram** (Graphviz DOT) rather than an animated,
zoomable physics graph. The `dot` engine lays the resources out in clean,
aligned columns:

    Internet   →   EC2 instances   →   IAM roles   →   S3 buckets

so connections and labels never overlap. Edges that lie on a discovered attack
path are drawn bold red; sensitive buckets are red; every node carries a clear
multi-line label. The DOT string is rendered by Streamlit's built-in
``st.graphviz_chart`` (no system Graphviz binary or extra dependency required).
"""

from __future__ import annotations

from core import graph_engine

# Categorical colour per node type (validated: distinct under CVD; identity is
# also carried by node shape + text label, never colour alone).
_NODE_STYLE = {
    "internet": {"fill": "#8b5cf6", "shape": "doublecircle"},
    "ec2": {"fill": "#3b82f6", "shape": "box"},
    "iam_role": {"fill": "#f59e0b", "shape": "hexagon"},
    "s3": {"fill": "#10b981", "shape": "cylinder"},
}
_SENSITIVE_FILL = "#ef4444"
_ATTACK_EDGE = "#ef4444"
_NORMAL_EDGE = "#94a3b8"
_ONPATH_BORDER = "#f8fafc"
_OFFPATH_BORDER = "#334155"
_FONT = "Helvetica,Arial,sans-serif"

# Column order (left → right) used to align ranks.
_LAYER_ORDER = ["internet", "ec2", "iam_role", "s3"]


def _esc(text):
    """Escape a string for use inside a DOT double-quoted literal."""
    return str(text).replace("\\", "\\\\").replace('"', '\\"')


def _node_label(node, data):
    """Build a clear, multi-line node label."""
    ntype = data.get("type")
    if ntype == "internet":
        return "Internet"
    if ntype == "ec2":
        status = "public" if data.get("public") else "private"
        return f"{node}\\n({status})"
    if ntype == "iam_role":
        status = "ADMIN" if data.get("admin") else "role"
        return f"{node}\\n[{status}]"
    if ntype == "s3":
        status = "SENSITIVE" if data.get("sensitive") else "standard"
        return f"{node}\\n({status})"
    return str(node)


def build_dot(result):
    """Return a Graphviz DOT string for the analysed resources."""
    resources = result["resources"]
    graph = graph_engine.build_graph(resources)

    # Edges / nodes that lie on any attack path.
    attack_edges, attack_nodes = set(), set()
    for finding in result["findings"]:
        path = finding["path"]
        attack_nodes.update(path)
        for i in range(len(path) - 1):
            attack_edges.add((path[i], path[i + 1]))

    # Group node ids by type so we can force column alignment via rank=same.
    by_type = {t: [] for t in _LAYER_ORDER}
    for node, data in graph.nodes(data=True):
        by_type.setdefault(data.get("type", "internet"), []).append((node, data))

    lines = [
        "digraph cloudpath {",
        "  rankdir=LR;",
        "  bgcolor=\"transparent\";",
        "  splines=true;",
        "  nodesep=0.45;",
        '  ranksep="1.15 equally";',
        "  pad=0.3;",
        f'  node [style="filled", fontname="{_FONT}", fontsize=11, '
        'fontcolor="#0b1120", penwidth=1.6, margin="0.16,0.09"];',
        f'  edge [fontname="{_FONT}", fontsize=9, arrowsize=0.8];',
    ]

    # Emit nodes, grouped into same-rank columns for clean alignment.
    for ntype in _LAYER_ORDER:
        nodes = sorted(by_type.get(ntype, []), key=lambda x: x[0])
        if not nodes:
            continue
        lines.append("  { rank=same;")
        for node, data in nodes:
            style = _NODE_STYLE.get(ntype, {"fill": "#64748b", "shape": "box"})
            fill = style["fill"]
            if ntype == "s3" and data.get("sensitive"):
                fill = _SENSITIVE_FILL
            on_path = node in attack_nodes
            border = _ONPATH_BORDER if on_path else _OFFPATH_BORDER
            shape = style["shape"]
            extra_style = ',rounded' if ntype == "ec2" else ''
            lines.append(
                f'    "{_esc(node)}" [label="{_node_label(node, data)}", '
                f'shape={shape}, fillcolor="{fill}", color="{border}", '
                f'penwidth={3 if on_path else 1.4}, style="filled{extra_style}"];'
            )
        lines.append("  }")

    # Emit edges.
    for src, dst, data in graph.edges(data=True):
        on_path = (src, dst) in attack_edges
        relation = str(data.get("relation", "")).replace("_", " ")
        color = _ATTACK_EDGE if on_path else _NORMAL_EDGE
        fontcolor = _ATTACK_EDGE if on_path else "#64748b"
        penwidth = 2.6 if on_path else 1.3
        lines.append(
            f'  "{_esc(src)}" -> "{_esc(dst)}" '
            f'[label=" {relation} ", color="{color}", fontcolor="{fontcolor}", '
            f'penwidth={penwidth}];'
        )

    lines.append("}")
    return "\n".join(lines)


# Backwards-compatible alias (older callers used render_attack_graph()).
def render_attack_graph(result, height=None):
    return build_dot(result)


def legend_items():
    """Return (label, colour) pairs for a UI legend."""
    return [
        ("Internet", _NODE_STYLE["internet"]["fill"]),
        ("EC2 instance", _NODE_STYLE["ec2"]["fill"]),
        ("IAM role", _NODE_STYLE["iam_role"]["fill"]),
        ("S3 bucket", _NODE_STYLE["s3"]["fill"]),
        ("Sensitive S3 / attack path", _SENSITIVE_FILL),
    ]
