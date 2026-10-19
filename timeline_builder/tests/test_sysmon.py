"""Unit tests for the sysmon parser against public test contract behavior."""
import json
import tempfile
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from timeline_builder.parsers.sysmon import parse


def _write_tmp(lines):
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
    for line in lines:
        f.write(line + "\n")
    f.close()
    return f.name


def test_parser_sysmon_basic_process_start():
    """PARSER-SYSMON: a process_start record must yield event_type
    process_start with a non-null exact_locator."""
    path = _write_tmp([
        json.dumps({"event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
                    "computer": "WS-01", "user": "u1", "event_type": "process_start",
                    "image": "powershell.exe", "parent_image": "winword.exe"})
    ])
    events = list(parse(path))
    os.unlink(path)
    assert len(events) == 1
    assert events[0]["event_type"] == "process_start"
    assert events[0]["exact_locator"] is not None
    assert events[0]["parser_status"] == "ok"


def test_damaged_row_quarantined():
    """DAMAGED-ROW: malformed JSON must be quarantined, not raise."""
    path = _write_tmp(["{broken-json"])
    events = list(parse(path))
    os.unlink(path)
    assert len(events) == 1
    assert events[0]["parser_status"] == "quarantined"
    assert "json_decode_error" in events[0]["quarantine_reason"]


def test_missing_locator_flagged():
    """MISSING-LOCATOR: a record with no event_id must be flagged invalid_output."""
    path = _write_tmp([
        json.dumps({"timestamp": "2026-01-01T00:00:00Z", "event_type": "process_start"})
    ])
    events = list(parse(path))
    os.unlink(path)
    assert events[0]["parser_status"] == "invalid_output"


def test_duplicate_event_ids_detected_downstream():
    """DUPLICATE-EVENT: two identical (source, locator) pairs must yield
    identical event_id, so downstream deduplication can act on it.
    The sysmon parser itself does not dedup (each line is a distinct
    locator by line number); this test documents that guarantee holds
    when the same file is parsed twice, not within a single pass."""
    path = _write_tmp([
        json.dumps({"event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
                    "event_type": "process_start", "image": "a.exe"})
    ])
    events_a = list(parse(path))
    events_b = list(parse(path))
    os.unlink(path)
    assert events_a[0]["event_id"] == events_b[0]["event_id"]


def test_invalid_timestamp_quarantined():
    """External review finding 7: a malformed timestamp string must be
    quarantined, not silently trusted into utc_time where the final
    lexicographic sort could place it anywhere."""
    path = _write_tmp([
        json.dumps({"event_id": "e1", "timestamp": "NOT-A-VALID-DATE",
                    "event_type": "process_start", "image": "a.exe"})
    ])
    events = list(parse(path))
    os.unlink(path)
    assert events[0]["parser_status"] == "invalid_output"
    assert "invalid_timestamp_format" in events[0]["quarantine_reason"]
    assert events[0]["utc_time"] is None


if __name__ == "__main__":
    test_parser_sysmon_basic_process_start()
    test_damaged_row_quarantined()
    test_missing_locator_flagged()
    test_duplicate_event_ids_detected_downstream()
    test_invalid_timestamp_quarantined()
    print("All sysmon parser tests: PASS")
