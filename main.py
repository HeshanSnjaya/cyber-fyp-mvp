import json
import sys
import networkx as nx


def load_mock_data():
    resources = {
        "ec2": [
            {
                "id": "EC2-WebServer-1",
                "public": True,
                "iam_role": "Role-S3Admin",
                "description": "Public-facing web server with admin role"
            },
            {
                "id": "EC2-AppServer-2",
                "public": False,
                "iam_role": "Role-S3ReadOnly",
                "description": "Internal application server"
            },
            {
                "id": "EC2-DevServer-3",
                "public": True,
                "iam_role": "Role-LambdaExec",
                "description": "Dev server accidentally left public"
            },
            {
                "id": "EC2-Internal-4",
                "public": False,
                "iam_role": None,
                "description": "Internal server with no IAM role"
            },
        ],
        "iam_roles": [
            {
                "id": "Role-S3Admin",
                "s3_access": ["S3-CustomerData", "S3-Logs"],
                "description": "Full admin access to customer data and logs"
            },
            {
                "id": "Role-S3ReadOnly",
                "s3_access": ["S3-PublicAssets"],
                "description": "Read-only access to public assets"
            },
            {
                "id": "Role-LambdaExec",
                "s3_access": ["S3-BackupDB"],
                "description": "Lambda execution role with backup access"
            },
        ],
        "s3": [
            {
                "id": "S3-CustomerData",
                "sensitive": True,
                "description": "Contains PII and customer records"
            },
            {
                "id": "S3-Logs",
                "sensitive": False,
                "description": "Application logs"
            },
            {
                "id": "S3-PublicAssets",
                "sensitive": False,
                "description": "Static website assets"
            },
            {
                "id": "S3-BackupDB",
                "sensitive": True,
                "description": "Database backups with credentials"
            },
        ],
    }
    return resources


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


def score_path(path, graph):
    score = 0

    if path[0] == "Internet":
        score += 5

    target_node = path[-1]
    node_data = graph.nodes[target_node]
    if node_data.get("sensitive", False):
        score += 5

    if len(path) <= 4:
        score += 2

    if score >= 10:
        severity = "HIGH"
    elif score >= 7:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {"score": score, "severity": severity}


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

    results = []
    for i, path in enumerate(attack_paths, 1):
        scoring = score_path(path, graph)
        path_str = " -> ".join(path)

        if scoring["severity"] == "HIGH":
            label = "[CRITICAL]"
        elif scoring["severity"] == "MEDIUM":
            label = "[WARNING]"
        else:
            label = "[INFO]"

        print(f"  {label} Attack Path #{i}")
        print(f"    Path:     {path_str}")
        print(f"    Hops:     {len(path) - 1}")
        print(f"    Score:    {scoring['score']}/12")
        print(f"    Severity: {scoring['severity']}")
        print()

        results.append({
            "path": path,
            "path_string": path_str,
            "hops": len(path) - 1,
            "score": scoring["score"],
            "severity": scoring["severity"],
        })

    print("-" * 60)
    print(f"  Summary: {len(attack_paths)} path(s) detected")
    high = sum(1 for r in results if r["severity"] == "HIGH")
    medium = sum(1 for r in results if r["severity"] == "MEDIUM")
    low = sum(1 for r in results if r["severity"] == "LOW")
    print(f"  HIGH: {high} | MEDIUM: {medium} | LOW: {low}")
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
                "score": scoring["score"],
                "severity": scoring["severity"],
            })
        output_json(results)
    else:
        print_results(attack_paths, graph)


if __name__ == "__main__":
    main()
