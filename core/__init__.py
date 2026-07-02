"""Core analysis engine for the Graph-Based Cloud Attack Path Analyzer.

This package contains the reusable, UI-agnostic building blocks:

* :mod:`core.cvss`         - CVSS v3.1 scoring (spec-accurate).
* :mod:`core.graph_engine` - Resource graph construction & path discovery.
* :mod:`core.threat_intel` - Human-readable threat + remediation intelligence.
* :mod:`core.analyzer`     - Orchestrator tying everything together.
* :mod:`core.credentials`  - Encrypted, project-local AWS key storage.
* :mod:`core.database`     - SQLite scan-history persistence.
* :mod:`core.data_sources` - Pluggable data providers (mock JSON / live AWS).
"""

__all__ = [
    "cvss",
    "graph_engine",
    "threat_intel",
    "analyzer",
    "credentials",
    "database",
    "data_sources",
]

__version__ = "2.0.0"
