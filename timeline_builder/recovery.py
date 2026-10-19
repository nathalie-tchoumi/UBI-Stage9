"""Reconstructs the exfiltrated archive from the raw TCP stream.

Deliberately independent of tshark's --export-objects (see decision-log
D-002): that heuristic misidentified the server's 8-byte "accepted"
response as a second exfiltration object. This module re-derives the
archive directly from the client->server HTTP body bytes, using the
declared Content-Length as the authoritative boundary.
"""
import hashlib
import subprocess
from pathlib import Path


def extract_client_payload(pcap_path: str, tcp_stream: int, client_ip: str) -> bytes:
    """Reassemble the raw TCP payload sent by client_ip on tcp_stream,
    in frame order, using per-frame tcp.payload extraction so direction
    is unambiguous (only frames sourced from client_ip are included).
    """
    cmd = [
        "tshark", "-r", pcap_path,
        "-Y", f"tcp.stream == {tcp_stream} && ip.src == {client_ip}",
        "-T", "fields", "-e", "tcp.payload",
        "-E", "separator=/s", "-E", "quote=n",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    hex_blob = "".join(
        line.strip().replace(":", "")
        for line in result.stdout.splitlines()
        if line.strip()
    )
    return bytes.fromhex(hex_blob)


def split_http_body(raw_bytes: bytes) -> tuple[dict, bytes, bool]:
    """Split concatenated HTTP request bytes into headers and body.
    Returns (headers_dict, body_bytes, is_request). Body length is
    trusted only insofar as it matches Content-Length; caller must
    verify.

    is_request distinguishes a genuine HTTP *request* (starts with a
    method like POST/GET) from an HTTP *response* (starts with
    "HTTP/1.1 ..."). Without this check, feeding the server's side of
    the conversation (e.g. by swapping client_ip for the server IP by
    mistake) reconstructs the server's small ack response instead of
    the exfiltrated archive, while length_match still reports True
    since the ack's own Content-Length matches its own tiny body --
    a false positive this check is designed to catch (external review
    finding 9, direct callback to decision-log D-002's original
    confusion between the archive and the "accepted" ack).
    """
    header_end = raw_bytes.find(b"\r\n\r\n")
    if header_end == -1:
        raise ValueError("no header/body boundary (\\r\\n\\r\\n) found in stream")
    header_blob = raw_bytes[:header_end].decode("ascii", errors="replace")
    body = raw_bytes[header_end + 4:]

    lines = header_blob.split("\r\n")
    request_line = lines[0] if lines else ""
    is_request = request_line.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD "))

    headers = {}
    for line in lines[1:]:  # skip request/status line
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers, body, is_request


def reconstruct(pcap_path: str, tcp_stream: int, client_ip: str) -> dict:
    """Full reconstruction pipeline. Returns a dict with the recovered
    bytes and verification facts, ready to be written to disk and cited
    with exact locators.
    """
    raw = extract_client_payload(pcap_path, tcp_stream, client_ip)
    headers, body, is_request = split_http_body(raw)

    declared_length = int(headers.get("Content-Length", -1))
    actual_length = len(body)

    if not is_request:
        raise ValueError(
            "extracted bytes are an HTTP response, not a request -- "
            "client_ip is likely wrong (this looks like the server's "
            "side of the conversation, not the client's exfiltration "
            "payload). length_match would still report True here, "
            "which is exactly the false-positive this check prevents."
        )

    return {
        "headers": headers,
        "body": body,
        "declared_content_length": declared_length,
        "actual_body_length": actual_length,
        "length_match": declared_length == actual_length,
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "is_request": is_request,
    }
