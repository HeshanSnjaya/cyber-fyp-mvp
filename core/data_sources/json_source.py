"""Mock / sample data source: loads bundled JSON resource inventory.

This is the offline path used for demonstrations and for the original MVP's
``mock_data.json``. It normalizes the file into the shared schema and fills in
default fields the richer UI expects (region, encryption, etc.).
"""

from __future__ import annotations

import json
import os

from .base import DataSource, DataSourceError

_DEFAULT_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "mock_data.json"
)


class JSONDataSource(DataSource):
    name = "json"
    label = "Sample Data (bundled JSON)"

    def __init__(self, path=None, **_ignored):
        self.path = path or _DEFAULT_FILE

    def fetch(self, progress=None):
        self._report(progress, 0.1, f"Loading {os.path.basename(self.path)}")
        if not os.path.exists(self.path):
            raise DataSourceError(f"Sample data file not found: {self.path}")
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except json.JSONDecodeError as exc:
            raise DataSourceError(f"Invalid JSON in {self.path}: {exc}") from exc

        self._report(progress, 0.6, "Normalizing resources")
        resources = _normalize(raw)
        self._report(progress, 1.0, "Sample data loaded")
        return resources


def _normalize(raw):
    """Fill defaults so sample data has the same fields as live AWS data."""
    ec2 = []
    for item in raw.get("ec2", []):
        ec2.append(
            {
                "id": item["id"],
                "public": bool(item.get("public")),
                "iam_role": item.get("iam_role"),
                "description": item.get("description", ""),
                "region": item.get("region", "sample-region"),
                "public_ip": item.get("public_ip", "203.0.113.10" if item.get("public") else None),
                "source": "sample",
            }
        )

    iam_roles = []
    for item in raw.get("iam_roles", []):
        # Sample data marks admin via naming convention ("Admin" in the id) or
        # an explicit flag if present.
        admin = bool(item.get("admin")) or "Admin" in item["id"]
        iam_roles.append(
            {
                "id": item["id"],
                "s3_access": list(item.get("s3_access", [])),
                "admin": admin,
                "description": item.get("description", ""),
                "source": "sample",
            }
        )

    s3 = []
    for item in raw.get("s3", []):
        s3.append(
            {
                "id": item["id"],
                "sensitive": bool(item.get("sensitive")),
                "description": item.get("description", ""),
                "encrypted": item.get("encrypted", False),
                "public_access_blocked": item.get("public_access_blocked", True),
                "region": item.get("region", "sample-region"),
                "source": "sample",
            }
        )

    return {"ec2": ec2, "iam_roles": iam_roles, "s3": s3}
