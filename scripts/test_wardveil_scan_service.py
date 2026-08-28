#!/usr/bin/env python3
"""Exercise the request-bound Wardveil Scan service and fail-closed boundary."""

from __future__ import annotations

import hashlib
import json
import socket
import sys
import threading
import urllib.error
import urllib.request
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_clamav import ClamAVConfig, ClamAVVerdict  # noqa: E402
from reference.wardveil_clamav_runtime import ClamAVRuntimePolicy  # noqa: E402
from reference.wardveil_scan_service import (  # noqa: E402
    SCAN_PATH,
    CallerCredential,
    ScanServiceRequest,
    ScanServiceRequestError,
    WardveilScanService,
    build_http_server,
    sign_scan_request,
)

FIXED_NOW = datetime(2026, 8, 28, 13, 36, 54, tzinfo=timezone.utc)
SECRET = b"s" * 32
RESOURCE_ID = "drive:space-1:file:node-1"


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
        return self.mode != "health_unavailable"

    def version(self) -> str:
        if self.mode == "health_unknown":
            raise RuntimeError("version unavailable")
        if self.mode == "stale_health":
            return "ClamAV 1.4.6/27000/Thu Aug 20 06:27:08 2026"
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
        if self.mode == "unsupported":
            return ClamAVVerdict(
                completed=False,
                malware_match=False,
                error_code="unsupported_resource",
                digest_sha256=digest,
            )
        return ClamAVVerdict(
            completed=True,
            malware_match=False,
            digest_sha256=digest,
        )


def credential(*, active: bool = True) -> CallerCredential:
    return CallerCredential(
        caller_id="goreecloud-drive",
        key_id="scan-current",
        secret=SECRET,
        resource_types=frozenset({"drive_file"}),
        active=active,
    )


def service(mode: str = "clean", *, active: bool = True) -> tuple[WardveilScanService, FakeClamAVClient]:
    client = FakeClamAVClient(mode)
    cred = credential(active=active)
    return (
        WardveilScanService(
            credentials={(cred.caller_id, cred.key_id): cred},
            client=client,
            policy=ClamAVRuntimePolicy(
                max_signature_age=timedelta(hours=48),
                health_validity=timedelta(minutes=5),
            ),
            now=lambda: FIXED_NOW,
        ),
        client,
    )


def request_for(content: bytes, **changes: object) -> ScanServiceRequest:
    request = ScanServiceRequest(
        caller_id="goreecloud-drive",
        key_id="scan-current",
        timestamp=FIXED_NOW.isoformat(),
        nonce="nonce-001",
        resource_type="drive_file",
        resource_id=RESOURCE_ID,
        digest_sha256=hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
        action="upload_finalize",
        correlation_id="corr-001",
        signature="0" * 64,
    )
    request = replace(request, **changes)
    return replace(request, signature=sign_scan_request(request, SECRET))


def expect_service_error(code: str, fn) -> None:
    try:
        fn()
    except ScanServiceRequestError as exc:
        assert exc.code == code, (exc.code, code)
    else:
        raise AssertionError(f"expected {code}")


def test_consumer_compatible_records() -> None:
    content = b"Wardveil clean consumer integration sample\n"
    scan_service, _ = service("clean")
    envelope = scan_service.scan(request_for(content), content)
    record = envelope["scan_record"]
    assert record["record_type"] == "scan_finding"
    assert record["result"] == "clean"
    assert "scan_result" not in record
    assert envelope["resource_digest_sha256"] == hashlib.sha256(content).hexdigest()
    assert record["producer"] == {"id": "wardveil-scan-clamav", "authoritative": True}
    assert record["scope"] == {"resource_type": "drive_file", "resource_id": RESOURCE_ID}
    assert any(ref.endswith(":clean") for ref in record["evidence_refs"])
    assert any(ref.startswith("wardveil:clamav-health:") for ref in record["evidence_refs"])
    assert "Wardveil clean consumer integration sample" not in json.dumps(envelope)


def test_malicious_and_unavailable_semantics() -> None:
    content = b"sample"
    malicious_service, _ = service("malicious")
    malicious = malicious_service.scan(request_for(content), content)
    assert malicious["scan_record"]["result"] == "malicious"
    assert any("Eicar-Test-Signature" in ref for ref in malicious["scan_record"]["evidence_refs"])

    unavailable_service, _ = service("unavailable")
    unavailable = unavailable_service.scan(request_for(content), content)
    assert unavailable["scan_record"]["result"] == "unknown"

    unsupported_service, _ = service("unsupported")
    unsupported = unsupported_service.scan(request_for(content), content)
    assert unsupported["scan_record"]["result"] == "unsupported"


def test_stale_health_downgrades_clean_but_not_malicious() -> None:
    content = b"sample"
    stale_service, _ = service("stale_health")
    assert stale_service.scan(request_for(content), content)["scan_record"]["result"] == "unknown"

    malicious_service, client = service("malicious")
    client.version = lambda: "ClamAV 1.4.6/27000/Thu Aug 20 06:27:08 2026"  # type: ignore[method-assign]
    assert malicious_service.scan(request_for(content), content)["scan_record"]["result"] == "malicious"


def test_digest_and_size_mismatch_fail_before_scan() -> None:
    content = b"changed"
    scan_service, client = service("clean")
    bad_digest = request_for(content, digest_sha256="0" * 64)
    expect_service_error("resource_digest_mismatch", lambda: scan_service.scan(bad_digest, content))
    bad_size = request_for(content, size_bytes=len(content) + 1, nonce="nonce-002")
    expect_service_error("resource_size_mismatch", lambda: scan_service.scan(bad_size, content))
    assert client.scan_calls == 0


def test_signature_timestamp_and_caller_fail_before_scan() -> None:
    content = b"sample"
    scan_service, client = service("clean")
    bad_signature = replace(request_for(content), signature="f" * 64)
    expect_service_error("scan_signature_invalid", lambda: scan_service.scan(bad_signature, content))

    old = request_for(content, timestamp=(FIXED_NOW - timedelta(minutes=5)).isoformat(), nonce="nonce-002")
    expect_service_error("scan_request_timestamp_outside_window", lambda: scan_service.scan(old, content))

    unknown = request_for(content, caller_id="goreecloud-browser", nonce="nonce-003")
    expect_service_error("scan_caller_not_authorized", lambda: scan_service.scan(unknown, content))
    assert client.scan_calls == 0


def test_resource_scope_is_least_privilege() -> None:
    content = b"sample"
    scan_service, client = service("clean")
    request = request_for(content, resource_type="browser_download")
    expect_service_error("scan_resource_type_not_authorized", lambda: scan_service.scan(request, content))
    assert client.scan_calls == 0


def test_inactive_caller_fails_closed() -> None:
    content = b"sample"
    scan_service, client = service("clean", active=False)
    expect_service_error("scan_caller_not_authorized", lambda: scan_service.scan(request_for(content), content))
    assert client.scan_calls == 0


def test_exact_replay_returns_identical_envelope_without_rescan() -> None:
    content = b"sample"
    scan_service, client = service("clean")
    request = request_for(content)
    first = scan_service.scan(request, content)
    second = scan_service.scan(request, content)
    assert first == second
    assert client.scan_calls == 1


def test_conflicting_nonce_reuse_fails_closed() -> None:
    first_content = b"first"
    second_content = b"second"
    scan_service, client = service("clean")
    scan_service.scan(request_for(first_content), first_content)
    conflicting = request_for(second_content, nonce="nonce-001", correlation_id="corr-002")
    expect_service_error("scan_nonce_conflict", lambda: scan_service.scan(conflicting, second_content))
    assert client.scan_calls == 1


def http_request(
    port: int,
    content: bytes,
    *,
    request: ScanServiceRequest | None = None,
    include_signature: bool = True,
) -> tuple[int, dict]:
    request = request or request_for(content)
    headers = {
        "Content-Type": "application/octet-stream",
        "X-Wardveil-Caller-ID": request.caller_id,
        "X-Wardveil-Key-ID": request.key_id,
        "X-Wardveil-Timestamp": request.timestamp,
        "X-Wardveil-Nonce": request.nonce,
        "X-Wardveil-Resource-Type": request.resource_type,
        "X-Wardveil-Resource-ID": request.resource_id,
        "X-Wardveil-Digest-SHA256": request.digest_sha256,
        "X-Wardveil-Size-Bytes": str(request.size_bytes),
        "X-Wardveil-Action": request.action,
        "X-Wardveil-Correlation-ID": request.correlation_id,
    }
    if include_signature:
        headers["X-Wardveil-Signature"] = request.signature
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{SCAN_PATH}",
        data=content,
        method="POST",
        headers=headers,
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


def test_http_auth_binding_and_generic_errors() -> None:
    scan_service, _ = service("clean")
    server = build_http_server(scan_service, port=available_loopback_port())
    assert server.server_address[0] == "127.0.0.1"
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        content = b"authenticated scan"
        status, payload = http_request(port, content, include_signature=False)
        assert status == 401
        assert payload == {"error": "scan_request_rejected"}

        status, payload = http_request(port, content)
        assert status == 200
        assert payload["scan_record"]["result"] == "clean"
        assert "scan_result" not in payload["scan_record"]

        bad = request_for(content, digest_sha256="f" * 64, nonce="nonce-http-bad")
        status, payload = http_request(port, content, request=bad)
        assert status == 422
        assert payload == {"error": "scan_request_rejected"}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def main() -> int:
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(f"Wardveil authenticated Scan service tests passed ({len(tests)} cases).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
