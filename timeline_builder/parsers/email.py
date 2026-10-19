"""Parser for the .eml email evidence source."""
import hashlib
import email
from email import policy
from email.utils import parsedate_to_datetime
from pathlib import Path
from timeline_builder.schema import make_event

SOURCE_NAME = "eml"


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _convert_date_header(raw_date):
    """Convert an RFC 2822 Date header to ISO-8601 UTC. Returns None if
    the header is absent or unparseable, rather than ever letting the
    literal Date header string (or nothing) end up in utc_time, which
    previously sorted every email event before all other events in
    timeline.csv regardless of when the email actually happened
    (external review finding 5).
    """
    if not raw_date:
        return None
    try:
        dt = parsedate_to_datetime(raw_date)
        if dt.tzinfo is None:
            return None
        return dt.isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError):
        return None


def parse(path: str):
    """Yield one normalized email_delivery event per .eml file, plus one
    event per attachment found, each carrying the attachment's own SHA-256
    (computed from decoded bytes, not trusted from any header)."""
    p = Path(path)
    artifact_sha256 = _file_sha256(p)

    with open(p, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    message_id = msg.get("Message-ID")
    missing_message_id = message_id is None
    raw_date = msg.get("Date")
    converted_date = _convert_date_header(raw_date)

    yield make_event(
        event_type="email_delivery",
        utc_time=converted_date,
        original_time=raw_date,
        source_timezone="UTC",
        source=SOURCE_NAME,
        artifact_path=str(path),
        artifact_sha256=artifact_sha256,
        exact_locator="header:top",
        host=None,
        user=msg.get("To"),
        activity=f"email from {msg.get('From')} subject={msg.get('Subject')!r}",
        parser_status="invalid_output" if missing_message_id else "ok",
        quarantine_reason="missing_message_id_header" if missing_message_id else None,
        raw={"from": msg.get("From"), "to": msg.get("To"), "subject": msg.get("Subject")},
    )

    part_index = 0
    for part in msg.walk():
        filename = part.get_filename()
        if not filename:
            continue
        part_index += 1
        payload = part.get_payload(decode=True) or b""
        attachment_sha256 = hashlib.sha256(payload).hexdigest()

        yield make_event(
            event_type="email_attachment",
            utc_time=converted_date,
            original_time=raw_date,
            source_timezone="UTC",
            source=SOURCE_NAME,
            artifact_path=str(path),
            artifact_sha256=artifact_sha256,
            exact_locator=f"attachment:{part_index}:{filename}",
            activity=f"attachment {filename} ({len(payload)} bytes decoded)",
            raw={"filename": filename, "content_type": part.get_content_type(),
                 "sha256": attachment_sha256, "size_bytes": len(payload)},
        )
