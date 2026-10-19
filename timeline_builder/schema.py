"""Common normalized event schema for the Stage 9 timeline builder.

Every parser must emit dicts matching this shape via `make_event()`.
Never construct the dict literally in a parser: always go through this
function so every source produces identically-structured output and
event_id derivation stays consistent.
"""
import hashlib
from datetime import datetime
from typing import Optional, Any


def validate_iso8601(raw_timestamp):
    """Returns the timestamp unchanged if it parses as valid ISO-8601,
    otherwise None. Callers must quarantine the record when this
    returns None rather than trusting a malformed string into utc_time,
    since the final timeline sort is lexicographic on this field
    (external review finding 7): an unvalidated bad string could sort
    anywhere in the output silently.
    """
    if not raw_timestamp:
        return None
    try:
        datetime.fromisoformat(raw_timestamp.replace("Z", "+00:00"))
        return raw_timestamp
    except (ValueError, AttributeError):
        return None

REQUIRED_FIELDS = [
    "event_id", "event_type", "utc_time", "original_time",
    "source_timezone", "source", "artifact_path", "artifact_sha256",
    "exact_locator", "correlation_id", "host", "user", "activity",
    "attack_technique", "confidence", "primary_or_supporting",
    "alternative_interpretation", "notes", "parser_status",
    "quarantine_reason", "raw",
]


def derive_event_id(source: str, exact_locator: str, event_type: str) -> str:
    """Deterministic event_id: stable across re-runs, used for dedup.

    Must include event_type: a single locator (e.g. one pcap frame) can
    legitimately produce more than one distinct normalized event (a
    generic network_connection plus a specific http_request on the same
    frame). Omitting event_type collapses those into one and silently
    drops the more specific event -- this was caught in D-006 after it
    erased the exfiltration POST event from timeline.csv.
    """
    digest = hashlib.sha256(f"{source}:{exact_locator}:{event_type}".encode()).hexdigest()
    return digest[:16]


def make_event(
    *,
    event_type: str,
    utc_time: Optional[str],
    original_time: Optional[str],
    source_timezone: str,
    source: str,
    artifact_path: str,
    artifact_sha256: str,
    exact_locator: str,
    host: Optional[str] = None,
    user: Optional[str] = None,
    activity: Optional[str] = None,
    correlation_id: Optional[str] = None,
    parser_status: str = "ok",
    quarantine_reason: Optional[str] = None,
    raw: Any = None,
) -> dict:
    event = {
        "event_id": derive_event_id(source, exact_locator, event_type),
        "event_type": event_type,
        "utc_time": utc_time,
        "original_time": original_time,
        "source_timezone": source_timezone,
        "source": source,
        "artifact_path": artifact_path,
        "artifact_sha256": artifact_sha256,
        "exact_locator": exact_locator,
        "correlation_id": correlation_id,
        "host": host,
        "user": user,
        "activity": activity,
        "attack_technique": None,
        "confidence": None,
        "primary_or_supporting": None,
        "alternative_interpretation": None,
        "notes": None,
        "parser_status": parser_status,
        "quarantine_reason": quarantine_reason,
        "raw": raw,
    }
    missing = [f for f in REQUIRED_FIELDS if f not in event]
    assert not missing, f"make_event() missing fields: {missing}"
    return event
