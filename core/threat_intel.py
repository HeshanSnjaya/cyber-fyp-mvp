"""Threat intelligence: turn a raw attack path into an analyst-grade report.

For each discovered path this module produces:

* A plain-English narrative of the compound risk.
* A per-hop breakdown explaining *why* each edge is dangerous.
* MITRE ATT&CK technique mappings (Cloud matrix).
* Prioritized, node-specific remediation guidance.

None of this changes the CVSS score; it is the "detailed info to the user"
layer that explains the real-world threat behind each number.
"""

from __future__ import annotations

# MITRE ATT&CK techniques keyed by the graph edge relation they correspond to.
MITRE_BY_RELATION = {
    "public_access": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1190/",
    },
    "assumes_role": {
        "id": "T1552.005",
        "name": "Unsecured Credentials: Cloud Instance Metadata API",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1552/005/",
    },
    "s3_access": {
        "id": "T1530",
        "name": "Data from Cloud Storage",
        "tactic": "Collection",
        "url": "https://attack.mitre.org/techniques/T1530/",
    },
}

# Additional technique surfaced whenever a role is assumed (lateral movement).
VALID_ACCOUNTS = {
    "id": "T1078.004",
    "name": "Valid Accounts: Cloud Accounts",
    "tactic": "Privilege Escalation / Lateral Movement",
    "url": "https://attack.mitre.org/techniques/T1078/004/",
}

RELATION_VERB = {
    "public_access": "is reachable from",
    "assumes_role": "assumes",
    "s3_access": "can read/write",
}


def _hop_explanation(src, dst, relation, graph):
    """Explain a single edge in the attack chain."""
    dst_data = graph.nodes[dst]
    if relation == "public_access":
        return (
            f"**{dst}** is exposed to the public internet. An attacker needs no "
            f"prior access or credentials to reach it — this is the entry point "
            f"of the attack chain."
        )
    if relation == "assumes_role":
        admin = dst_data.get("admin")
        privilege = "highly privileged (admin/write)" if admin else "scoped"
        return (
            f"**{src}** carries an instance profile that lets it assume **{dst}**. "
            f"By querying the EC2 instance metadata service, an attacker who "
            f"controls {src} inherits this {privilege} IAM role — no password "
            f"required. This is a security-authority (scope) change."
        )
    if relation == "s3_access":
        sensitive = dst_data.get("sensitive")
        tag = "SENSITIVE" if sensitive else "non-sensitive"
        return (
            f"**{dst}** ({tag}) is accessible using the permissions of **{src}**. "
            f"The attacker can now exfiltrate the objects stored in this bucket."
        )
    return f"**{src}** connects to **{dst}** via {relation}."


def build_path_intel(path, graph, scoring):
    """Return a rich intelligence report for a single scored attack path."""
    edges = []
    techniques = []
    seen_tech = set()

    for i in range(len(path) - 1):
        src, dst = path[i], path[i + 1]
        relation = graph.edges[src, dst].get("relation", "connects_to")
        edges.append(
            {
                "source": src,
                "target": dst,
                "relation": relation,
                "explanation": _hop_explanation(src, dst, relation, graph),
            }
        )
        tech = MITRE_BY_RELATION.get(relation)
        if tech and tech["id"] not in seen_tech:
            techniques.append(tech)
            seen_tech.add(tech["id"])
        if relation == "assumes_role" and VALID_ACCOUNTS["id"] not in seen_tech:
            techniques.append(VALID_ACCOUNTS)
            seen_tech.add(VALID_ACCOUNTS["id"])

    target = graph.nodes[path[-1]]
    entry = path[1] if len(path) > 1 else path[0]
    narrative = (
        f"An attacker starting from the public internet can compromise the "
        f"internet-facing resource **{entry}**, pivot through the IAM "
        f"permissions it inherits, and ultimately reach the sensitive data "
        f"store **{path[-1]}** in **{len(path) - 1} hops**. Each individual "
        f"misconfiguration on this path may look low-risk in isolation, but "
        f"chained together they form a "
        f"**{scoring['severity']}** ({scoring['score']:.1f}/10) attack path."
    )

    return {
        "narrative": narrative,
        "hops": edges,
        "mitre": techniques,
        "remediation": build_remediation(path, graph),
        "business_impact": _business_impact(target, scoring),
    }


def _business_impact(target, scoring):
    desc = target.get("description", "sensitive data")
    if scoring["severity"] in ("CRITICAL", "HIGH"):
        return (
            f"Exposure of **{target['id']}** ({desc}) would likely constitute a "
            f"reportable data breach. Depending on the data classification this "
            f"can trigger regulatory penalties (GDPR/UK-GDPR, PCI-DSS), customer "
            f"notification obligations, and reputational damage."
        )
    return (
        f"**{target['id']}** ({desc}) is reachable but the overall exploitability "
        f"or impact is limited. Treat as a hardening opportunity."
    )


# Remediation catalogue keyed by node type. Each entry is (title, detail).
REMEDIATION_CATALOGUE = {
    "ec2": [
        (
            "Remove unnecessary public exposure",
            "Detach the public IP / Elastic IP if the instance does not need to "
            "be internet-facing, or place it behind an Application Load Balancer "
            "with a WAF.",
        ),
        (
            "Tighten Security Groups",
            "Restrict inbound rules to specific IP ranges and ports; eliminate "
            "0.0.0.0/0 rules on management ports (22, 3389).",
        ),
        (
            "Enforce IMDSv2",
            "Require IMDSv2 (HttpTokens=required) so that SSRF cannot trivially "
            "steal the instance role's credentials.",
        ),
    ],
    "iam_role": [
        (
            "Apply least privilege",
            "Replace broad or admin policies with permissions scoped to the "
            "exact S3 buckets and actions the workload needs.",
        ),
        (
            "Constrain resource ARNs",
            "Avoid Resource:\"*\"; pin S3 statements to specific bucket ARNs and "
            "object prefixes.",
        ),
        (
            "Add permission boundaries & conditions",
            "Use permission boundaries and condition keys (aws:SourceVpc, "
            "aws:SourceIp) to limit where the role can be used.",
        ),
    ],
    "s3": [
        (
            "Enable default encryption",
            "Turn on SSE-KMS default encryption and deny unencrypted uploads via "
            "a bucket policy.",
        ),
        (
            "Block public access",
            "Enable S3 Block Public Access at the account and bucket level.",
        ),
        (
            "Enable logging & versioning",
            "Turn on server access logging / CloudTrail data events and object "
            "versioning to detect and recover from exfiltration or tampering.",
        ),
    ],
}


def build_remediation(path, graph):
    """Collect prioritized, de-duplicated remediation for the nodes on a path."""
    recommendations = []
    for node in path:
        node_type = graph.nodes[node].get("type")
        for title, detail in REMEDIATION_CATALOGUE.get(node_type, []):
            recommendations.append(
                {"resource": node, "title": title, "detail": detail}
            )
    return recommendations
