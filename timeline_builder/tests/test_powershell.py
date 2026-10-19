"""Unit tests for the PowerShell Operational parser."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from timeline_builder.parsers.powershell import parse


def _write_tmp(lines):
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
    for line in lines:
        f.write(line + "\n")
    f.close()
    return f.name


def test_basic_script_block_event():
    """A well-formed record with event_id yields event_type
    script_block_logged and parser_status ok."""
    path = _write_tmp([
        json.dumps({"event_id": 4104, "timestamp": "2026-01-01T00:00:00Z",
                    "script_name": "test.ps1", "script_block": "Get-Process",
                    "binding": "abc123"})
    ])
    events = list(parse(path))
    os.unlink(path)
    assert len(events) == 1
    assert events[0]["event_type"] == "script_block_logged"
    assert events[0]["parser_status"] == "ok"
    assert events[0]["correlation_id"] == "abc123"


def test_no_host_field_left_none_not_inferred():
    """This source never carries a host field. The parser must leave
    host=None rather than guessing or borrowing one from elsewhere."""
    path = _write_tmp([
        json.dumps({"event_id": 4104, "timestamp": "2026-01-01T00:00:00Z",
                    "script_name": "test.ps1", "script_block": "Get-Process"})
    ])
    events = list(parse(path))
    os.unlink(path)
    assert events[0]["host"] is None


def test_damaged_row_quarantined():
    """DAMAGED-ROW: malformed JSON must be quarantined, not raise."""
    path = _write_tmp(["{broken-json"])
    events = list(parse(path))
    os.unlink(path)
    assert events[0]["parser_status"] == "quarantined"


def test_missing_locator_flagged():
    """MISSING-LOCATOR: a record with no event_id must be flagged invalid_output."""
    path = _write_tmp([
        json.dumps({"timestamp": "2026-01-01T00:00:00Z", "script_name": "test.ps1"})
    ])
    events = list(parse(path))
    os.unlink(path)
    assert events[0]["parser_status"] == "invalid_output"


def test_invalid_timestamp_quarantined():
    """External review finding 7: a malformed timestamp string must be
    quarantined, not silently trusted into utc_time."""
    path = _write_tmp([
        json.dumps({"event_id": 4104, "timestamp": "NOT-A-VALID-DATE",
                    "script_name": "test.ps1", "script_block": "Get-Process"})
    ])
    events = list(parse(path))
    os.unlink(path)
    assert events[0]["parser_status"] == "invalid_output"
    assert "invalid_timestamp_format" in events[0]["quarantine_reason"]
    assert events[0]["utc_time"] is None


if __name__ == "__main__":
    test_basic_script_block_event()
    test_no_host_field_left_none_not_inferred()
    test_damaged_row_quarantined()
    test_missing_locator_flagged()
    test_invalid_timestamp_quarantined()
    print("All powershell parser tests: PASS")
