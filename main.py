import json
import os
import sys
import networkx as nx


MOCK_DATA_FILE = os.path.join(os.path.dirname(__file__), "mock_data.json")


def load_mock_data(path=MOCK_DATA_FILE):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_graph(resources):
    G = nx.DiGraph()
    G.add_node("Internet", type="internet")

    for ec2 in resources["ec2"]:
        G.add_node(ec2["id"], type="ec2", **ec2)
        if ec2["public"]:
            G.add_edge("Internet", ec2["id"], relation="public_access")
        if ec2["iam_role"]:
            G.add_edge(ec2["id"], ec2["iam_role"], relation="assumes_role")

    for role in resources["iam_roles"]:
        G.add_node(role["id"], type="iam_role", **role)
        for bucket_id in role["s3_access"]:
            G.add_edge(role["id"], bucket_id, relation="s3_access")

    for bucket in resources["s3"]:
        G.add_node(bucket["id"], type="s3", **bucket)

    return G


def find_attack_paths(graph, resources):
    attack_paths = []
    sensitive_buckets = [b["id"] for b in resources["s3"] if b["sensitive"]]

    for target in sensitive_buckets:
        if nx.has_path(graph, "Internet", target):
            paths = nx.all_simple_paths(graph, "Internet", target)
            for path in paths:
                attack_paths.append(path)

    return attack_paths


# CVSS v3.1 base metric weights (per the official specification).
CVSS_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    # Privileges Required is scope-dependent: the second value applies when
    # Scope is Changed.
    "PR": {"N": (0.85, 0.85), "L": (0.62, 0.68), "H": (0.27, 0.50)},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def derive_cvss_metrics(path, graph):
    """Map an attack path's properties onto CVSS v3.1 base metrics."""
    target = graph.nodes[path[-1]]
    internet_entry = path[0] == "Internet"
    hops = len(path) - 1
    role_in_path = [n for n in path if graph.nodes[n].get("type") == "iam_role"]
    crosses_role = len(role_in_path) > 0
    admin_role = any("Admin" in n for n in role_in_path)
    sensitive_target = target.get("sensitive", False)

    return {
        # Internet-reachable entry is a Network vector; otherwise Local.
        "AV": "N" if internet_entry else "L",
        # Short chains are easy to traverse; longer ones add complexity.
        "AC": "L" if hops <= 3 else "H",
        # Public exposure needs no prior privileges; internal needs some.
        "PR": "N" if internet_entry else "L",
        # No user interaction in these automated reachability paths.
        "UI": "N",
        # Assuming an IAM role crosses a security authority -> Scope Changed.
        "S": "C" if crosses_role else "U",
        # Sensitive data fully compromises confidentiality.
        "C": "H" if sensitive_target else "L",
        # Admin (write-capable) roles in the path threaten integrity.
        "I": "H" if admin_role else "N",
        # These paths model data access, not service disruption.
        "A": "N",
    }


def _roundup(value):
    """CVSS Roundup: smallest one-decimal value >= the input."""
    rounded = int(value * 100000)
    if rounded % 10000 == 0:
        return rounded / 100000.0
    return (int(rounded / 10000) + 1) / 10.0


def cvss_base_score(metrics):
    """Compute the CVSS v3.1 base score from derived metrics."""
    scope_changed = metrics["S"] == "C"

    iss = 1 - (
        (1 - CVSS_WEIGHTS["C"][metrics["C"]])
        * (1 - CVSS_WEIGHTS["I"][metrics["I"]])
        * (1 - CVSS_WEIGHTS["A"][metrics["A"]])
    )

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    pr_weight = CVSS_WEIGHTS["PR"][metrics["PR"]][1 if scope_changed else 0]
    exploitability = (
        8.22
        * CVSS_WEIGHTS["AV"][metrics["AV"]]
        * CVSS_WEIGHTS["AC"][metrics["AC"]]
        * pr_weight
        * CVSS_WEIGHTS["UI"][metrics["UI"]]
    )

    if impact <= 0:
        return 0.0

    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def cvss_severity(score):
    """CVSS v3.1 qualitative severity rating."""
    if score == 0.0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def cvss_vector(metrics):
    """Render the CVSS v3.1 base vector string."""
    order = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    return "CVSS:3.1/" + "/".join(f"{k}:{metrics[k]}" for k in order)


def score_path(path, graph):
    metrics = derive_cvss_metrics(path, graph)
    score = cvss_base_score(metrics)
    return {
        "score": score,
        "severity": cvss_severity(score),
        "cvss_vector": cvss_vector(metrics),
    }


def print_results(attack_paths, graph):
    print("=" * 60)
    print("  GRAPH-BASED ATTACK PATH ANALYSIS RESULTS")
    print("=" * 60)
    print()

    if not attack_paths:
        print("  No attack paths detected.")
        print("  All sensitive resources appear to be properly isolated.")
        print()
        return []

    print(f"  Found {len(attack_paths)} attack path(s):\n")

    labels = {
        "CRITICAL": "[CRITICAL]",
        "HIGH": "[HIGH]",
        "MEDIUM": "[WARNING]",
        "LOW": "[INFO]",
        "NONE": "[INFO]",
    }

    results = []
    for i, path in enumerate(attack_paths, 1):
        scoring = score_path(path, graph)
        path_str = " -> ".join(path)
        label = labels.get(scoring["severity"], "[INFO]")

        print(f"  {label} Attack Path #{i}")
        print(f"    Path:     {path_str}")
        print(f"    Hops:     {len(path) - 1}")
        print(f"    CVSS:     {scoring['score']:.1f}/10 ({scoring['severity']})")
        print(f"    Vector:   {scoring['cvss_vector']}")
        print()

        results.append({
            "path": path,
            "path_string": path_str,
            "hops": len(path) - 1,
            "cvss_score": scoring["score"],
            "cvss_vector": scoring["cvss_vector"],
            "severity": scoring["severity"],
        })

    print("-" * 60)
    print(f"  Summary: {len(attack_paths)} path(s) detected")
    critical = sum(1 for r in results if r["severity"] == "CRITICAL")
    high = sum(1 for r in results if r["severity"] == "HIGH")
    medium = sum(1 for r in results if r["severity"] == "MEDIUM")
    low = sum(1 for r in results if r["severity"] in ("LOW", "NONE"))
    print(f"  CRITICAL: {critical} | HIGH: {high} | "
          f"MEDIUM: {medium} | LOW: {low}")
    print("=" * 60)

    return results


def output_json(results):
    output = {
        "tool": "Graph-Based Attack Path Analyzer",
        "version": "1.0.0-mvp",
        "total_paths": len(results),
        "findings": results,
    }
    print(json.dumps(output, indent=2))


def main():
    json_mode = "--json" in sys.argv

    resources = load_mock_data()
    graph = build_graph(resources)

    if not json_mode:
        print(f"\n  Graph built: {graph.number_of_nodes()} nodes, "
              f"{graph.number_of_edges()} edges\n")

    attack_paths = find_attack_paths(graph, resources)

    if json_mode:
        results = []
        for path in attack_paths:
            scoring = score_path(path, graph)
            results.append({
                "path": path,
                "path_string": " -> ".join(path),
                "hops": len(path) - 1,
                "cvss_score": scoring["score"],
                "cvss_vector": scoring["cvss_vector"],
                "severity": scoring["severity"],
            })
        output_json(results)
    else:
        print_results(attack_paths, graph)


if __name__ == "__main__":
    main()
