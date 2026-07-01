"""CVSS v3.1 base-score scoring.

The formulas below follow the official FIRST CVSS v3.1 specification so that
scores and vector strings match public calculators exactly. This module is a
faithful extraction of the scoring logic from the original MVP, kept isolated
so both the CLI and the Streamlit UI share one source of truth.
"""

from __future__ import annotations

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

# Human-readable names for each metric value, used by the UI to explain a score.
METRIC_LABELS = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S": {"U": "Unchanged", "C": "Changed"},
    "C": {"H": "High", "L": "Low", "N": "None"},
    "I": {"H": "High", "L": "Low", "N": "None"},
    "A": {"H": "High", "L": "Low", "N": "None"},
}

METRIC_NAMES = {
    "AV": "Attack Vector",
    "AC": "Attack Complexity",
    "PR": "Privileges Required",
    "UI": "User Interaction",
    "S": "Scope",
    "C": "Confidentiality",
    "I": "Integrity",
    "A": "Availability",
}


def derive_cvss_metrics(path, graph):
    """Map an attack path's properties onto CVSS v3.1 base metrics."""
    target = graph.nodes[path[-1]]
    internet_entry = path[0] == "Internet"
    hops = len(path) - 1
    role_in_path = [n for n in path if graph.nodes[n].get("type") == "iam_role"]
    crosses_role = len(role_in_path) > 0
    # An admin/write-capable role is flagged either by an explicit graph
    # attribute (live AWS analysis) or by naming convention (mock data).
    admin_role = any(
        graph.nodes[n].get("admin") or "Admin" in n for n in role_in_path
    )
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
    rounded = int(round(value * 100000))
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


def explain_metrics(metrics):
    """Return a list of (name, value, label) tuples for UI display."""
    order = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    return [
        (METRIC_NAMES[k], metrics[k], METRIC_LABELS[k][metrics[k]])
        for k in order
    ]


def score_path(path, graph):
    """Score a single attack path, returning score, severity and vector."""
    metrics = derive_cvss_metrics(path, graph)
    score = cvss_base_score(metrics)
    return {
        "metrics": metrics,
        "score": score,
        "severity": cvss_severity(score),
        "cvss_vector": cvss_vector(metrics),
    }
