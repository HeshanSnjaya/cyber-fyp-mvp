"""Analysis orchestrator.

Given a data source, this module runs the full pipeline:

    fetch resources -> build graph -> find attack paths -> score (CVSS)
                    -> enrich (threat intel) -> summarize

and returns one structured ``result`` dict that both the CLI and the Streamlit
UI consume. Keeping the orchestration here means the front-ends contain no
analysis logic.
"""

from __future__ import annotations

from datetime import datetime, timezone

from . import cvss, graph_engine, threat_intel
from .data_sources import get_source


def run_analysis(mode="json", progress=None, **source_kwargs):
    """Run an end-to-end analysis and return a structured result dict.

    Parameters
    ----------
    mode : str
        ``"json"`` for bundled sample data or ``"aws"`` for a live scan.
    progress : callable, optional
        ``progress(fraction, message)`` callback for UI status updates.
    source_kwargs :
        Passed to the data source (e.g. AWS credentials/region).
    """
    source = get_source(mode, **source_kwargs)
    _report(progress, 0.05, f"Fetching resources from {source.label}")
    resources = source.fetch(progress=_scaled(progress, 0.05, 0.55))

    _report(progress, 0.6, "Building resource dependency graph")
    graph = graph_engine.build_graph(resources)

    _report(progress, 0.72, "Discovering attack paths")
    paths = graph_engine.find_attack_paths(graph, resources)

    _report(progress, 0.85, "Scoring paths & generating threat intelligence")
    findings = []
    for idx, path in enumerate(paths, 1):
        scoring = cvss.score_path(path, graph)
        intel = threat_intel.build_path_intel(path, graph, scoring)
        findings.append(
            {
                "id": idx,
                "path": path,
                "path_string": " -> ".join(path),
                "hops": len(path) - 1,
                "entry_point": path[1] if len(path) > 1 else path[0],
                "target": path[-1],
                "cvss_score": scoring["score"],
                "cvss_vector": scoring["cvss_vector"],
                "severity": scoring["severity"],
                "metrics": scoring["metrics"],
                "metric_explanation": cvss.explain_metrics(scoring["metrics"]),
                "intel": intel,
            }
        )

    # Rank findings: highest CVSS first, then fewest hops (easier to exploit).
    findings.sort(key=lambda f: (-f["cvss_score"], f["hops"]))
    for rank, finding in enumerate(findings, 1):
        finding["rank"] = rank

    account_id = getattr(source, "account_id", None)
    region = source_kwargs.get("region") if mode == "aws" else None

    result = {
        "meta": {
            "source": source.name,
            "source_label": source.label,
            "region": region,
            "account_id": account_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        "resources": resources,
        "graph_stats": graph_engine.graph_stats(graph),
        "summary": _summarize(findings),
        "findings": findings,
    }
    _report(progress, 1.0, "Analysis complete")
    return result


def _summarize(findings):
    def count(sev):
        return sum(1 for f in findings if f["severity"] == sev)

    max_cvss = max((f["cvss_score"] for f in findings), default=0.0)
    return {
        "total_paths": len(findings),
        "critical": count("CRITICAL"),
        "high": count("HIGH"),
        "medium": count("MEDIUM"),
        "low": count("LOW") + count("NONE"),
        "max_cvss": max_cvss,
        "highest_severity": findings[0]["severity"] if findings else "NONE",
    }


def _report(progress, fraction, message):
    if progress is not None:
        try:
            progress(fraction, message)
        except Exception:
            pass


def _scaled(progress, lo, hi):
    """Return a progress callback that maps [0,1] into the [lo,hi] band."""
    if progress is None:
        return None

    def inner(fraction, message):
        _report(progress, lo + (hi - lo) * max(0.0, min(1.0, fraction)), message)

    return inner
