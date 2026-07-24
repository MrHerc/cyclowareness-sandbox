"""Small shared helpers with no dependencies of their own."""
from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    """Timezone-aware UTC now.

    Used as the default for every timestamp column. Aware-UTC is the single
    representation the whole service standardises on; the frontend treats any
    datetime that arrives without an offset as UTC, so a SQLite round-trip
    (which drops the tzinfo) still renders correctly.
    """
    return datetime.now(timezone.utc)
