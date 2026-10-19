"""Parser for the network PCAP evidence source, via tshark -T fields."""
import csv
import hashlib
import io
import subprocess
from pathlib import Path
from timeline_builder.schema import make_event

SOURCE_NAME = "pcap"

FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst",
    "tcp.srcport", "tcp.dstport", "tcp.stream", "tcp.len",
    "http.request.method", "http.request.uri", "http.host",
    "http.response.code", "http.content_length", "dns.qry.name",
]


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _run_tshark_fields(path: str) -> list[dict]:
    cmd = ["tshark", "-r", path, "-T", "fields"]
    for field in FIELDS:
        cmd += ["-e", field]
    cmd += ["-E", "header=y", "-E", "separator=\t", "-E", "quote=n"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    reader = csv.DictReader(io.StringIO(result.stdout), delimiter="\t")
    return list(reader)


def parse(path: str):
    """Yield one normalized event per packet. TCP-only packets yield
    network_connection; packets carrying an HTTP request/response also
    yield a dedicated http event so the exfiltration transfer is
    directly queryable from the timeline, not buried in raw TCP noise.
    """
    p = Path(path)
    artifact_sha256 = _file_sha256(p)
    rows = _run_tshark_fields(path)

    for row in rows:
        frame_num = row["frame.number"]
        locator = f"frame:{frame_num}"
        epoch = row.get("frame.time_epoch", "").strip()
        utc_time = None
        if epoch:
            from datetime import datetime, timezone
            utc_time = datetime.fromtimestamp(float(epoch), tz=timezone.utc).isoformat().replace("+00:00", "Z")

        stream_id = row.get("tcp.stream") or None

        yield make_event(
            event_type="network_connection",
            utc_time=utc_time,
            original_time=epoch or None,
            source_timezone="UTC",
            source=SOURCE_NAME,
            artifact_path=str(path),
            artifact_sha256=artifact_sha256,
            exact_locator=locator,
            correlation_id=f"tcp_stream:{stream_id}" if stream_id is not None else None,
            activity=f"{row.get('ip.src')}:{row.get('tcp.srcport')} -> {row.get('ip.dst')}:{row.get('tcp.dstport')} len={row.get('tcp.len')}",
            raw=row,
        )

        method = row.get("http.request.method")
        resp_code = row.get("http.response.code")
        if method:
            yield make_event(
                event_type="http_request",
                utc_time=utc_time,
                original_time=epoch or None,
                source_timezone="UTC",
                source=SOURCE_NAME,
                artifact_path=str(path),
                artifact_sha256=artifact_sha256,
                exact_locator=locator,
                correlation_id=f"tcp_stream:{stream_id}" if stream_id is not None else None,
                activity=f"{method} {row.get('http.request.uri')} Host={row.get('http.host')} Content-Length={row.get('http.content_length')}",
                raw=row,
            )
        elif resp_code:
            yield make_event(
                event_type="http_response",
                utc_time=utc_time,
                original_time=epoch or None,
                source_timezone="UTC",
                source=SOURCE_NAME,
                artifact_path=str(path),
                artifact_sha256=artifact_sha256,
                exact_locator=locator,
                correlation_id=f"tcp_stream:{stream_id}" if stream_id is not None else None,
                activity=f"HTTP {resp_code} Content-Length={row.get('http.content_length')}",
                raw=row,
            )
