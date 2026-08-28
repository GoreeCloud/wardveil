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
    InMemoryReplayLedger,
    ScanServiceRequest,
    ScanServiceRequestError,
    WardveilScanService,
    build_http_server,
    credentials_from_json,
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
        return self.verdict(data)

    def verdict(self, data: bytes) -> ClamAVVerdict:
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


class BlockingClamAVClient(FakeClamAVClient):
    def __init__(self):
        super().__init__("clean")
        self.entered = threading.Event()
        self.release = threading.Event()

    def scan_bytes(self, data: bytes) -> ClamAVVerdict:
        self.scan_calls += 1
        self.entered.set()
        if not self.release.wait(timeout=2):
            raise RuntimeError("blocking scanner test timed out")
        return self.verdict(data)


def credential(*, active: bool = True) -> CallerCredential:
    return CallerCredential(
        caller_id="goreecloud-drive",
        key_id="scan-current",
        secret=SECRET,
        resource_types=frozenset({"drive_file"}),
        active=active,
    )


def build_service(
    client: FakeClamAVClient,
    *,
    active: bool = True,
    replay_ledger: InMemoryReplayLedger | None = None,
) -> WardveilScanService:
    cred = credential(active=active)
    return WardveilScanService(
        credentials={(cred.caller_id, cred.key_id): cred},
        client=client,
        policy=ClamAVRuntimePolicy(
            max_signature_age=timedelta(hours=48),
            health_validity=timedelta(minutes=5),
        ),
        replay_ledger=replay_ledger,
        now=lambda: FIXED_NOW,
    )


def service(
    mode: str = "clean",
    *,
    active: bool = True,
    replay_ledger: InMemoryReplayLedger | None = None,
) -> tuple[WardveilScanService, FakeClamAVClient]:
    client = FakeClamAVClient(mode)
    return build_service(client, active=active, replay_ledger=replay_ledger), client


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


def expect_value_error(fn) -> None:
    try:
        fn()
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_consumer_compatible_records() -> None:
    content = b"Wardveil clean consumer integration sample\n"
    scan_service, _ = service()
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


def test_malicious_unavailable_and_unsupported_semantics() -> None:
    content = b"sample"
    malicious_service, _ = service("malicious")
    malicious = malicious_service.scan(request_for(content), content)
    assert malicious["scan_record"]["result"] == "malicious"
    assert any("Eicar-Test-Signature" in ref for ref in malicious["scan_record"]["evidence_refs"])

    unavailable_service, _ = service("unavailable")
    assert unavailable_service.scan(request_for(content), content)["scan_record"]["result"] == "unknown"

    unsupported_service, _ = service("unsupported")
    assert unsupported_service.scan(request_for(content), content)["scan_record"]["result"] == "unsupported"


def test_stale_health_downgrades_clean_but_not_malicious() -> None:
    content = b"sample"
    stale_service, _ = service("stale_health")
    assert stale_service.scan(request_for(content), content)["scan_record"]["result"] == "unknown"

    malicious_service, client = service("malicious")
    client.version = lambda: "ClamAV 1.4.6/27000/Thu Aug 20 06:27:08 2026"  # type: ignore[method-assign]
    assert malicious_service.scan(request_for(content), content)["scan_record"]["result"] == "malicious"


def test_digest_and_size_mismatch_fail_before_scan() -> None:
    content = b"changed"
    scan_service, client = service()
    expect_service_error(
        "resource_digest_mismatch",
        lambda: scan_service.scan(request_for(content, digest_sha256="0" * 64), content),
    )
    expect_service_error(
        "resource_size_mismatch",
        lambda: scan_service.scan(
            request_for(content, size_bytes=len(content) + 1, nonce="nonce-002"),
            content,
        ),
    )
    assert client.scan_calls == 0


def test_signature_timestamp_and_unknown_caller_fail_before_scan() -> None:
    content = b"sample"
    scan_service, client = service()
    expect_service_error(
        "scan_signature_invalid",
        lambda: scan_service.scan(replace(request_for(content), signature="f" * 64), content),
    )
    expect_service_error(
        "scan_request_timestamp_outside_window",
        lambda: scan_service.scan(
            request_for(
                content,
                timestamp=(FIXED_NOW - timedelta(minutes=5)).isoformat(),
                nonce="nonce-002",
            ),
            content,
        ),
    )
    expect_service_error(
        "scan_caller_not_authorized",
        lambda: scan_service.scan(
            request_for(content, caller_id="goreecloud-browser", nonce="nonce-003"),
            content,
        ),
    )
    assert client.scan_calls == 0


def test_resource_scope_is_least_privilege() -> None:
    content = b"sample"
    scan_service, client = service()
    expect_service_error(
        "scan_resource_type_not_authorized",
        lambda: scan_service.scan(request_for(content, resource_type="browser_download"), content),
    )
    assert client.scan_calls == 0


def test_inactive_caller_fails_closed() -> None:
    content = b"sample"
    scan_service, client = service(active=False)
    expect_service_error(
        "scan_caller_not_authorized",
        lambda: scan_service.scan(request_for(content), content),
    )
    assert client.scan_calls == 0


def test_credential_json_is_strict_and_placeholder_fails() -> None:
    valid = json.dumps(
        [
            {
                "caller_id": "goreecloud-drive",
                "key_id": "scan-current",
                "secret": "s" * 32,
                "resource_types": ["drive_file"],
                "active": True,
            }
        ]
    )
    assert credentials_from_json(valid)[
        ("goreecloud-drive", "scan-current")
    ].active is True
    expect_value_error(
        lambda: credentials_from_json(valid.replace('"active": true', '"active": "false"'))
    )
    expect_value_error(
        lambda: credentials_from_json(
            valid.replace('"resource_types": ["drive_file"]', '"resource_types": "drive_file"')
        )
    )
    expect_value_error(
        lambda: credentials_from_json(valid.replace("s" * 32, "REPLACE_WITH_PRODUCTION_SECRET"))
    )


def test_exact_replay_returns_identical_envelope_without_rescan() -> None:
    content = b"sample"
    scan_service, client = service()
    request = request_for(content)
    first = scan_service.scan(request, content)
    second = scan_service.scan(request, content)
    assert first == second
    assert client.scan_calls == 1


def test_conflicting_nonce_reuse_fails_closed() -> None:
    scan_service, client = service()
    scan_service.scan(request_for(b"first"), b"first")
    expect_service_error(
        "scan_nonce_conflict",
        lambda: scan_service.scan(
            request_for(b"second", nonce="nonce-001", correlation_id="corr-002"),
            b"second",
        ),
    )
    assert client.scan_calls == 1


def test_replay_ledger_is_bounded_and_expiring() -> None:
    ledger = InMemoryReplayLedger(max_entries=1, ttl=timedelta(seconds=1))
    first = request_for(b"first")
    second = request_for(b"second", nonce="nonce-002", correlation_id="corr-002")
    assert ledger.claim(first, "a" * 64, now=FIXED_NOW)[0] == "new"
    assert ledger.claim(second, "b" * 64, now=FIXED_NOW)[0] == "capacity"
    assert ledger.claim(second, "b" * 64, now=FIXED_NOW + timedelta(seconds=2))[0] == "new"


def test_concurrent_exact_request_does_not_duplicate_scan() -> None:
    content = b"concurrent"
    client = BlockingClamAVClient()
    scan_service = build_service(client)
    request = request_for(content)
    outcome: dict[str, object] = {}

    def first_scan() -> None:
        try:
            outcome["result"] = scan_service.scan(request, content)
        except Exception as exc:  # pragma: no cover
            outcome["error"] = exc

    thread = threading.Thread(target=first_scan)
    thread.start()
    assert client.entered.wait(timeout=1)
    expect_service_error(
        "scan_request_already_in_progress",
        lambda: scan_service.scan(request, content),
    )
    client.release.set()
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert "error" not in outcome
    assert isinstance(outcome.get("result"), dict)
    assert client.scan_calls == 1


def available_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


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
        return exc.code, json.loads(raw) if raw else {}


def test_http_auth_binding_and_generic_errors() -> None:
    scan_service, _ = service()
    server = build_http_server(scan_service, port=available_loopback_port())
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

        status, payload = http_request(
            port,
            content,
            request=request_for(content, digest_sha256="f" * 64, nonce="nonce-http-bad"),
        )
        assert status == 422
        assert payload == {"error": "scan_request_rejected"}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_http_rejects_bad_signature_before_body_ingestion() -> None:
    scan_service, _ = service()
    server = build_http_server(scan_service, port=available_loopback_port())
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        declared_size = 100_000
        request = replace(
            request_for(b""),
            nonce="nonce-preauth",
            correlation_id="corr-preauth",
            digest_sha256="a" * 64,
            size_bytes=declared_size,
            signature="f" * 64,
        )
        headers = [
            "POST /v1/scan HTTP/1.1",
            f"Host: 127.0.0.1:{port}",
            "Content-Type: application/octet-stream",
            f"Content-Length: {declared_size}",
            f"X-Wardveil-Caller-ID: {request.caller_id}",
            f"X-Wardveil-Key-ID: {request.key_id}",
            f"X-Wardveil-Timestamp: {request.timestamp}",
            f"X-Wardveil-Nonce: {request.nonce}",
            f"X-Wardveil-Resource-Type: {request.resource_type}",
            f"X-Wardveil-Resource-ID: {request.resource_id}",
            f"X-Wardveil-Digest-SHA256: {request.digest_sha256}",
            f"X-Wardveil-Size-Bytes: {request.size_bytes}",
            f"X-Wardveil-Action: {request.action}",
            f"X-Wardveil-Correlation-ID: {request.correlation_id}",
            f"X-Wardveil-Signature: {request.signature}",
            "Connection: close",
            "",
            "",
        ]
        response_parts: list[bytes] = []
        with socket.create_connection(("127.0.0.1", port), timeout=1) as client:
            client.settimeout(1)
            client.sendall("\r\n".join(headers).encode("ascii"))
            client.shutdown(socket.SHUT_WR)
            while True:
                try:
                    chunk = client.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                response_parts.append(chunk)
        response = b"".join(response_parts)
        assert b" 401 " in response
        assert b"scan_request_rejected" in response
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def main() -> int:
    tests = [
        value
        for name, value in sorted(globals().items())
        if name.startswith("test_") and callable(value)
    ]
    for test in tests:
        test()
    print(f"Wardveil authenticated Scan service tests passed ({len(tests)} cases).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
