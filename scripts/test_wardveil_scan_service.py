#!/usr/bin/env python3
"""Exercise the authenticated Wardveil Scan service and its fail-closed boundary."""

from __future__ import annotations

import hashlib
import json
import socket
import sys
import threading
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_clamav import ClamAVConfig, ClamAVVerdict  # noqa: E402
from reference.wardveil_clamav_runtime import ClamAVRuntimePolicy  # noqa: E402
from reference.wardveil_scan_service import (  # noqa: E402
    SCAN_PATH,
    ScanServiceRequest,
    ScanServiceRequestError,
    WardveilScanService,
    build_http_server,
)


FIXED_NOW = datetime(2026, 8, 28, 13, 36, 54, tzinfo=timezone.utc)


class FakeClamAVClient:
    def __init__(self, mode: str = "clean"):
        self.mode = mode
        self.scan_calls = 0
        self.config = ClamAVConfig(
            unix_socket=None,
            tcp_host="127.0.0.1",
            tcp_port=3310,
            timeout_seconds=1,
            max_stream_bytes=1024 * 1024,
            chunk_bytes=4096,
            producer_id="wardveil-scan-clamav",
        )

    def ping(self) -> bool:
        return True

    def version(self) -> str:
        return "ClamAV 1.4.6/28106/Fri Aug 28 06:27:08 2026"

    def scan_bytes(self, data: bytes) -> ClamAVVerdict:
        self.scan_calls += 1
        digest = hashlib.sha256(data).hexdigest()
        if self.mode == "malicious":
            return ClamAVVerdict(
                completed=True,
                malware_match=True,
                signature="Eicar-Test-Signature",
                digest_sha256=digest,
            )
        if self.mode == "unavailable":
            return ClamAVVerdict(
                completed=False,
                malware_match=False,
                error_code="clamd_unavailable:ConnectionRefusedError",
                digest_sha256=digest,
            )
        return ClamAVVerdict(
            completed=True,
            malware_match=False,
            digest_sha256=digest,
        )


def service(mode: str = "clean") -> tuple[WardveilScanService, FakeClamAVClient]:
    client = FakeClamAVClient(mode)
    return (
        WardveilScanService(
            client=client,
            policy=ClamAVRuntimePolicy(
                max_signature_age=timedelta(hours=48),
                health_validity=timedelta(minutes=5),
            ),
            now=lambda: FIXED_NOW,
        ),
        client,
    )


def request_for(content: bytes) -> ScanServiceRequest:
    return ScanServiceRequest(
        resource_type="drive_file",
        resource_id="drive:space-1:file:node-1",
        digest_sha256=hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
        action="upload_finalize",
    )


def test_service_records() -> None:
    content = b"Wardveil clean consumer integration sample\n"
    scan_service, _ = service("clean")
    envelope = scan_service.scan(request_for(content), content)
    record = envelope["scan_record"]
    assert record["record_type"] == "scan_finding"
    assert record["scan_result"] == "clean"
    assert "result" not in record
    assert record["producer"] == {
        "id": "wardveil-scan-clamav",
        "authoritative": True,
    }
    assert record["scope"] == {
        "resource_type": "drive_file",
        "resource_id": "drive:space-1:file:node-1",
    }
    assert any(ref.endswith(":clean") for ref in record["evidence_refs"])
    assert any(
        ref.startswith("wardveil:clamav-health:") for ref in record["evidence_refs"]
    )
    encoded = json.dumps(envelope)
    assert "Wardveil clean consumer integration sample" not in encoded

    malicious_service, _ = service("malicious")
    malicious = malicious_service.scan(request_for(content), content)
    assert malicious["scan_record"]["scan_result"] == "malicious"
    assert any(
        "Eicar-Test-Signature" in ref
        for ref in malicious["scan_record"]["evidence_refs"]
    )

    unavailable_service, _ = service("unavailable")
    unavailable = unavailable_service.scan(request_for(content), content)
    assert unavailable["scan_record"]["scan_result"] == "unknown"


def test_digest_mismatch_fails_before_scan() -> None:
    content = b"changed"
    scan_service, client = service("clean")
    bad = ScanServiceRequest(
        resource_type="drive_file",
        resource_id="drive:space-1:file:node-1",
        digest_sha256="0" * 64,
        size_bytes=len(content),
        action="upload_finalize",
    )
    try:
        scan_service.scan(bad, content)
    except ScanServiceRequestError as exc:
        assert exc.code == "resource_digest_mismatch"
    else:
        raise AssertionError("digest mismatch should fail")
    assert client.scan_calls == 0


def http_request(
    port: int,
    content: bytes,
    *,
    token: str | None,
    digest: str | None = None,
) -> tuple[int, dict]:
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{SCAN_PATH}",
        data=content,
        method="POST",
        headers={
            "Content-Type": "application/octet-stream",
            "X-Wardveil-Resource-Type": "drive_file",
            "X-Wardveil-Resource-ID": "drive:space-1:file:node-1",
            "X-Wardveil-Digest-SHA256": digest or hashlib.sha256(content).hexdigest(),
            "X-Wardveil-Size-Bytes": str(len(content)),
            "X-Wardveil-Action": "upload_finalize",
            **({"Authorization": f"Bearer {token}"} if token is not None else {}),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=2) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        payload = json.loads(raw) if raw else {}
        return exc.code, payload


def available_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def test_http_auth_and_binding() -> None:
    token = "t" * 64
    scan_service, _ = service("clean")
    server = build_http_server(scan_service, token, port=available_loopback_port())
    assert server.server_address[0] == "127.0.0.1"
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        content = b"authenticated scan"
        status, _ = http_request(port, content, token=None)
        assert status == 401

        status, payload = http_request(port, content, token=token)
        assert status == 200
        assert payload["scan_record"]["scan_result"] == "clean"

        status, payload = http_request(port, content, token=token, digest="f" * 64)
        assert status == 422
        assert payload == {"error": "resource_digest_mismatch"}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def main() -> int:
    test_service_records()
    test_digest_mismatch_fails_before_scan()
    test_http_auth_and_binding()
    print("Wardveil authenticated Scan service tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
