"""Parser for the Sysmon JSONL evidence source."""
import json
import hashlib
from pathlib import Path
from timeline_builder.schema import make_event, validate_iso8601

SOURCE_NAME = "sysmon"


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def parse(path: str):
    """Yield normalized events from a Sysmon JSONL file.

    Malformed lines are quarantined (parser_status='quarantined') rather
    than raised, per the DAMAGED-ROW test contract: the pipeline must
    continue past a bad line, not crash.
    """
    p = Path(path)
    artifact_sha256 = _file_sha256(p)

    with open(p, "r") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.rstrip("\n")
            if not line:
                continue
            locator = f"line:{line_num}"

            try:
                record = json.loads(line)
            except json.JSONDecodeError as e:
                yield make_event(
                    event_type="parse_error",
                    utc_time=None,
                    original_time=None,
                    source_timezone="UTC",
                    source=SOURCE_NAME,
                    artifact_path=str(path),
                    artifact_sha256=artifact_sha256,
                    exact_locator=locator,
                    parser_status="quarantined",
                    quarantine_reason=f"json_decode_error: {e}",
                    raw=line,
                )
                continue

            missing_locator = record.get("event_id") is None
            raw_timestamp = record.get("timestamp")
            validated_time = validate_iso8601(raw_timestamp)
            bad_timestamp = raw_timestamp is not None and validated_time is None

            if missing_locator or bad_timestamp:
                reasons = []
                if missing_locator:
                    reasons.append("missing_event_id")
                if bad_timestamp:
                    reasons.append(f"invalid_timestamp_format: {raw_timestamp!r}")
                status = "invalid_output"
                reason = "; ".join(reasons)
            else:
                status = "ok"
                reason = None

            yield make_event(
                event_type=record.get("event_type"),
                utc_time=validated_time,
                original_time=raw_timestamp,
                source_timezone="UTC",
                source=SOURCE_NAME,
                artifact_path=str(path),
                artifact_sha256=artifact_sha256,
                exact_locator=locator,
                host=record.get("computer"),
                user=record.get("user"),
                activity=f"{record.get('event_type')}: {record.get('image')} (parent: {record.get('parent_image')}) - {record.get('detail')}",
                correlation_id=record.get("evidence_binding"),
                parser_status=status,
                quarantine_reason=reason,
                raw=record,
            )
