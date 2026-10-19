"""Unit tests for the email parser against public test contract behavior."""
import os
import sys
import email.message

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from timeline_builder.parsers.email import parse


def _write_eml(path, message_id=None, attachment=False):
    msg = email.message.EmailMessage()
    msg["From"] = "sender@example.invalid"
    msg["To"] = "recipient@example.invalid"
    msg["Subject"] = "Test"
    if message_id:
        msg["Message-ID"] = message_id
    msg.set_content("body text")
    if attachment:
        msg.add_attachment(b"payload-bytes", maintype="application",
                            subtype="octet-stream", filename="test.txt")
    with open(path, "wb") as f:
        f.write(msg.as_bytes())


def test_parser_email_with_message_id():
    """PARSER-EMAIL: a message with Message-ID yields event_type
    email_delivery and parser_status ok."""
    path = "/tmp/test_email_with_id.eml"
    _write_eml(path, message_id="<case-1@invalid>")
    events = list(parse(path))
    os.unlink(path)
    delivery = [e for e in events if e["event_type"] == "email_delivery"][0]
    assert delivery["parser_status"] == "ok"


def test_parser_email_missing_message_id_flagged():
    """Real-world case encountered in sealed evidence: no Message-ID header
    present. Must be flagged, not silently accepted or fabricated."""
    path = "/tmp/test_email_no_id.eml"
    _write_eml(path, message_id=None)
    events = list(parse(path))
    os.unlink(path)
    delivery = [e for e in events if e["event_type"] == "email_delivery"][0]
    assert delivery["parser_status"] == "invalid_output"
    assert delivery["quarantine_reason"] == "missing_message_id_header"


def test_attachment_sha256_computed_not_trusted():
    """Attachment SHA-256 must be computed from decoded bytes, matching
    an independently computed hash of the same known payload."""
    import hashlib
    path = "/tmp/test_email_attachment.eml"
    _write_eml(path, message_id="<case-2@invalid>", attachment=True)
    events = list(parse(path))
    os.unlink(path)
    attachment = [e for e in events if e["event_type"] == "email_attachment"][0]
    expected = hashlib.sha256(b"payload-bytes").hexdigest()
    assert attachment["raw"]["sha256"] == expected


def test_date_header_converted_to_utc_time():
    """External review finding 5: a valid Date header must be converted
    to a real utc_time, not left None. Previously every email event
    sorted before all other timeline events regardless of when the
    email actually happened, since an empty string sorts first
    lexicographically."""
    path = "/tmp/test_email_with_date.eml"
    msg = email.message.EmailMessage()
    msg["From"] = "sender@example.invalid"
    msg["To"] = "recipient@example.invalid"
    msg["Subject"] = "Test"
    msg["Message-ID"] = "<case-3@invalid>"
    msg["Date"] = "Wed, 15 Jul 2026 11:46:41 +0000"
    msg.set_content("body text")
    with open(path, "wb") as f:
        f.write(msg.as_bytes())
    events = list(parse(path))
    os.unlink(path)
    delivery = [e for e in events if e["event_type"] == "email_delivery"][0]
    assert delivery["utc_time"] == "2026-07-15T11:46:41Z"


def test_missing_date_header_leaves_utc_time_none():
    """Confirms the real-evidence case (no Date header at all) still
    correctly yields None rather than a fabricated timestamp."""
    path = "/tmp/test_email_no_date.eml"
    msg = email.message.EmailMessage()
    msg["From"] = "sender@example.invalid"
    msg["To"] = "recipient@example.invalid"
    msg["Subject"] = "Test"
    msg["Message-ID"] = "<case-4@invalid>"
    msg.set_content("body text")
    with open(path, "wb") as f:
        f.write(msg.as_bytes())
    events = list(parse(path))
    os.unlink(path)
    delivery = [e for e in events if e["event_type"] == "email_delivery"][0]
    assert delivery["utc_time"] is None


if __name__ == "__main__":
    test_parser_email_with_message_id()
    test_parser_email_missing_message_id_flagged()
    test_attachment_sha256_computed_not_trusted()
    test_date_header_converted_to_utc_time()
    test_missing_date_header_leaves_utc_time_none()
    print("All email parser tests: PASS")
