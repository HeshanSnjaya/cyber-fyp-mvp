"""CloudPath CLI — Graph-Based Cloud Attack Path Analyzer.

The original MVP's command-line interface, now backed by the shared ``core``
engine so the CLI, the Streamlit UI (``app.py``) and any automation all use one
implementation of the graph, CVSS scoring and threat intelligence.

Usage
-----
    python main.py                 # analyze bundled sample data (pretty output)
    python main.py --json          # machine-readable JSON output
    python main.py --aws           # live AWS scan (uses saved project keys)
    python main.py --aws --json    # live AWS scan, JSON output

Live AWS mode reads credentials saved by the app under ``.secrets/`` (entered
via the Streamlit sidebar). It never uses environment or ~/.aws credentials.
"""

from __future__ import annotations

import json
import sys

from core import analyzer, credentials

SEVERITY_LABELS = {
    "CRITICAL": "[CRITICAL]",
    "HIGH": "[HIGH]",
    "MEDIUM": "[WARNING]",
    "LOW": "[INFO]",
    "NONE": "[INFO]",
}


def _aws_kwargs_or_exit():
    saved = credentials.load_credentials()
    if not saved:
        print(
            "No saved AWS credentials found. Start the app (`streamlit run "
            "app.py`), switch to Live AWS mode and save your keys first.",
            file=sys.stderr,
        )
        sys.exit(2)
    return {
        "aws_access_key_id": saved["aws_access_key_id"],
        "aws_secret_access_key": saved["aws_secret_access_key"],
        "region": saved.get("region", "us-east-1"),
        "aws_session_token": saved.get("aws_session_token"),
    }


def print_results(result):
    findings = result["findings"]
    stats = result["graph_stats"]
    summary = result["summary"]

    print(f"\n  Graph built: {stats['nodes']} nodes, {stats['edges']} edges")
    print(f"  Source: {result['meta']['source_label']}\n")

    print("=" * 60)
    print("  GRAPH-BASED ATTACK PATH ANALYSIS RESULTS")
    print("=" * 60)
    print()

    if not findings:
        print("  No attack paths detected.")
        print("  All sensitive resources appear to be properly isolated.\n")
        return

    print(f"  Found {len(findings)} attack path(s):\n")
    for f in findings:
        label = SEVERITY_LABELS.get(f["severity"], "[INFO]")
        print(f"  {label} Attack Path #{f['rank']}")
        print(f"    Path:     {f['path_string']}")
        print(f"    Hops:     {f['hops']}")
        print(f"    CVSS:     {f['cvss_score']:.1f}/10 ({f['severity']})")
        print(f"    Vector:   {f['cvss_vector']}")
        print()

    print("-" * 60)
    print(f"  Summary: {summary['total_paths']} path(s) detected")
    print(
        f"  CRITICAL: {summary['critical']} | HIGH: {summary['high']} | "
        f"MEDIUM: {summary['medium']} | LOW: {summary['low']}"
    )
    print("=" * 60)


def output_json(result):
    output = {
        "tool": "Graph-Based Attack Path Analyzer",
        "version": "2.0.0",
        "source": result["meta"]["source_label"],
        "total_paths": result["summary"]["total_paths"],
        "summary": result["summary"],
        "findings": [
            {
                "rank": f["rank"],
                "path": f["path"],
                "path_string": f["path_string"],
                "hops": f["hops"],
                "cvss_score": f["cvss_score"],
                "cvss_vector": f["cvss_vector"],
                "severity": f["severity"],
                "mitre": [t["id"] for t in f["intel"]["mitre"]],
            }
            for f in result["findings"]
        ],
    }
    print(json.dumps(output, indent=2))


def main():
    json_mode = "--json" in sys.argv
    aws_mode = "--aws" in sys.argv

    mode = "aws" if aws_mode else "json"
    kwargs = _aws_kwargs_or_exit() if aws_mode else {}

    result = analyzer.run_analysis(mode=mode, **kwargs)

    if json_mode:
        output_json(result)
    else:
        print_results(result)


if __name__ == "__main__":
    main()
