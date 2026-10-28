"""Datetime helpers for API output."""

from datetime import datetime, timezone


def iso_utc(value: datetime) -> str:
    """ISO-8601 with an explicit UTC offset.

    Mongo hands back naive datetimes that are UTC. Serialised without an offset, browsers parse
    them as local time, which shifted every age in the UI by the viewer's UTC offset.
    """
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()
