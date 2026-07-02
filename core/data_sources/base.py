"""Abstract data source contract."""

from __future__ import annotations

import abc


class DataSourceError(Exception):
    """Raised when a data source cannot produce resource data."""


class DataSource(abc.ABC):
    """A provider of normalized cloud resource inventory."""

    #: Short machine name, e.g. "json" or "aws".
    name: str = "base"
    #: Human label for the UI.
    label: str = "Base Source"

    @abc.abstractmethod
    def fetch(self, progress=None):
        """Return the normalized resource dict.

        ``progress`` is an optional callable ``progress(fraction, message)`` used
        to report incremental status to the UI. Implementations should call it
        as work proceeds but must tolerate it being ``None``.
        """

    def _report(self, progress, fraction, message):
        if progress is not None:
            try:
                progress(fraction, message)
            except Exception:
                pass
