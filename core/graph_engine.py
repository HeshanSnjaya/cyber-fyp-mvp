"""Resource dependency graph construction and attack-path discovery.

The graph models cloud reachability:

    Internet --public_access--> EC2 --assumes_role--> IAM Role --s3_access--> S3

Attack paths are simple (cycle-free) paths from the ``Internet`` node to any S3
bucket flagged ``sensitive``. This is the heart of the compound-misconfiguration
detection: individual edges may be benign, but a full chain from the public
internet to sensitive data is a critical, exploitable path.

Both data sources (mock JSON and live AWS) emit the same normalized schema, so
this engine is source-agnostic.
"""

from __future__ import annotations

import networkx as nx

INTERNET = "Internet"


def build_graph(resources):
    """Build a directed reachability graph from normalized resource data.

    ``resources`` must contain three lists: ``ec2``, ``iam_roles`` and ``s3``.
    Each item carries at least an ``id``; additional keys are stored as node
    attributes and surface later in the UI's detail panels.
    """
    G = nx.DiGraph()
    G.add_node(INTERNET, type="internet")

    # Register IAM roles and S3 buckets first so edges never reference a
    # missing node (live AWS data is not guaranteed to be internally ordered).
    for bucket in resources.get("s3", []):
        G.add_node(bucket["id"], **_node_attrs(bucket, "s3"))

    for role in resources.get("iam_roles", []):
        G.add_node(role["id"], **_node_attrs(role, "iam_role"))

    for ec2 in resources.get("ec2", []):
        G.add_node(ec2["id"], **_node_attrs(ec2, "ec2"))

    # Wire up the edges.
    for ec2 in resources.get("ec2", []):
        if ec2.get("public"):
            G.add_edge(INTERNET, ec2["id"], relation="public_access")
        role_id = ec2.get("iam_role")
        if role_id and G.has_node(role_id):
            G.add_edge(ec2["id"], role_id, relation="assumes_role")

    for role in resources.get("iam_roles", []):
        for bucket_id in role.get("s3_access", []):
            if G.has_node(bucket_id):
                G.add_edge(role["id"], bucket_id, relation="s3_access")

    return G


def _node_attrs(item, node_type):
    """Merge a resource dict into node attributes, forcing the type field."""
    attrs = dict(item)
    attrs["type"] = node_type
    return attrs


def find_attack_paths(graph, resources):
    """Find every simple path from the Internet to a sensitive S3 bucket."""
    attack_paths = []
    sensitive_buckets = [
        b["id"] for b in resources.get("s3", []) if b.get("sensitive")
    ]

    for target in sensitive_buckets:
        if graph.has_node(target) and nx.has_path(graph, INTERNET, target):
            for path in nx.all_simple_paths(graph, INTERNET, target):
                attack_paths.append(path)

    # Longest / most-direct paths first is less meaningful than a stable order;
    # sort by hop count so shorter (easier) chains surface predictably.
    attack_paths.sort(key=len)
    return attack_paths


def graph_stats(graph):
    """Return a small dict of graph metrics for dashboards."""
    type_counts = {}
    for _, data in graph.nodes(data=True):
        type_counts[data.get("type", "unknown")] = (
            type_counts.get(data.get("type", "unknown"), 0) + 1
        )
    return {
        "nodes": graph.number_of_nodes(),
        "edges": graph.number_of_edges(),
        "by_type": type_counts,
    }
