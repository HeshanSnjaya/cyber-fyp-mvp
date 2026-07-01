"""Pluggable data providers that all emit the same normalized schema.

    {
      "ec2":       [{"id", "public", "iam_role", "description", ...}],
      "iam_roles": [{"id", "s3_access": [...], "admin", "description", ...}],
      "s3":        [{"id", "sensitive", "description", ...}],
    }

Because every source produces this shape, the graph engine, CVSS scorer and UI
are completely decoupled from *where* the data came from.
"""

from .base import DataSource, DataSourceError
from .json_source import JSONDataSource
from .aws_source import AWSDataSource

__all__ = [
    "DataSource",
    "DataSourceError",
    "JSONDataSource",
    "AWSDataSource",
    "get_source",
]


def get_source(mode, **kwargs):
    """Factory: return a data source for ``mode`` ('json' or 'aws')."""
    mode = (mode or "json").lower()
    if mode in ("json", "mock", "sample"):
        return JSONDataSource(**kwargs)
    if mode in ("aws", "live"):
        return AWSDataSource(**kwargs)
    raise DataSourceError(f"Unknown data source mode: {mode!r}")
