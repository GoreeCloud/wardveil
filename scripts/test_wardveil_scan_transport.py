#!/usr/bin/env python3
from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from reference.wardveil_clamav import ClamAVVerdict
from reference.wardveil_clamav_runtime import ClamAVHealthEvidence
from reference.wardveil_scan_transport import (
    AuthenticatedScanService,
    CallerCredential,
    ScanTransportError,
    ScanTransportRequest,
    sign_scan_request,
)

NOW = datetime(2026, 8, 28, 13, 0, tzinfo=timezone.utc)
SECRET = b"a" * 32


class FakeScanner:
    def __init__(self, verdict: ClamAVVerdict):
        self.verdict = verdict
        self.config = SimpleNamespace(producer_id="wardveil-scan-clamav")
        self.calls = 0

    def scan_bytes(self, body: bytes) -> ClamAVVerdict:
        self.calls += 1
        if self.verdict.digest_sha256 is None:
            return replace(self.verdict, digest_sha256=hashlib.sha256(body).hexdigest())
        return self.verdict


def health(*, state: str = "healthy", freshness: str = "current", reasons: tuple[str, ...] = ()) -> ClamAVHealthEvidence:
    return ClamAVHealthEvidence(
        observed_at=NOW - timedelta(seconds=10),
        valid_until=NOW + timedelta(minutes=4),
        runtime_state=state,
        daemon_reachable=state != "unavailable",
        engine_version="1.4.3",
        database_version="28000",
        database_updated_at=NOW - timedelta(hours=1),
        signature_freshness=freshness,
        signature_age_seconds=3600,
        last_successful_scan_at=NOW - timedelta(minutes=1),
        scan_error_rate=0.0,
        scan_sample_size=100,
        configured_max_stream_bytes=25 * 1024 * 1024,
        transport="tcp",
        degraded_reasons=reasons,
    )


def credential() -> CallerCredential:
    return CallerCredential(
        caller_id="goreecloud-drive",
        key_id="scan-current",
        secret=SECRET,
        resource_types=frozenset({"drive_file"}),
    )


def signed_request(body: bytes, **changes) -> ScanTransportRequest:
    base = ScanTransportRequest(
        caller_id="goreecloud-drive",
        key_id="scan-current",
        timestamp=NOW.isoformat(),
        nonce="nonce-001",
        action="upload_finalize",
        resource_type="drive_file",
        resource_id="drive:11111111-1111-1111-1111-111111111111:file:22222222-2222-2222-2222-222222222222",
        correlation_id="corr-001",
        content_length=len(body),
        content_sha256=hashlib.sha256(body).hexdigest(),
        signature="0" * 64,
    )
    request = replace(base, **changes)
    return replace(request, signature=sign_scan_request(request, SECRET))


def service(verdict: ClamAVVerdict, scanner_health: ClamAVHealthEvidence | None = None):
    scanner = FakeScanner(verdict)
    target_health = scanner_health or health()
    svc = AuthenticatedScanService(
        scanner=scanner,
        health_provider=lambda: target_health,
        credentials={("goreecloud-drive", "scan-current"): credential()},
        now=lambda: NOW,
    )
    return svc, scanner


def expect_error(code: str, fn) -> None:
    try:
        fn()
    except ScanTransportError as exc:
        assert exc.code == code, (exc.code, code)
    else:
        raise AssertionError(f"expected {code}")


def test_clean_envelope_binds_digest_scope_and_health() -> None:
    body = b"clean-control"
    svc, _ = service(ClamAVVerdict(completed=True, malware_match=False))
    request = signed_request(body)
    envelope = svc.scan(request, body)
    record = envelope["scan_record"]
    assert envelope["resource_id"] == request.resource_id
    assert envelope["resource_digest_sha256"] == request.content_sha256
    assert record["record_type"] == "scan_finding"
    assert record["producer"]["authoritative"] is True
    assert record["scope"] == {"resource_type": "drive_file", "resource_id": request.resource_id}
    assert record["result"] == "clean"
    assert any(ref.startswith("clamav:sha256:") for ref in record["evidence_refs"])
    assert any(ref.startswith("wardveil:clamav-health:") for ref in record["evidence_refs"])


def test_degraded_health_turns_clean_unknown() -> None:
    body = b"clean-control"
    svc, _ = service(
        ClamAVVerdict(completed=True, malware_match=False),
        health(state="degraded", freshness="stale", reasons=("signature_database_stale",)),
    )
    record = svc.scan(signed_request(body), body)["scan_record"]
    assert record["result"] == "unknown"
    assert any(ref.startswith("wardveil:clamav-health:") for ref in record["evidence_refs"])


def test_malicious_remains_actionable_during_degraded_health() -> None:
    body = b"malware"
    svc, _ = service(
        ClamAVVerdict(completed=True, malware_match=True, signature="Eicar-Signature"),
        health(state="degraded", freshness="stale", reasons=("signature_database_stale",)),
    )
    record = svc.scan(signed_request(body), body)["scan_record"]
    assert record["result"] == "malicious"
    assert any(":found:Eicar-Signature" in ref for ref in record["evidence_refs"])


def test_scanner_unavailable_returns_unknown() -> None:
    body = b"payload"
    svc, _ = service(ClamAVVerdict(completed=False, malware_match=False, error_code="clamd_unavailable:TimeoutError"))
    assert svc.scan(signed_request(body), body)["scan_record"]["result"] == "unknown"


def test_unsupported_returns_unsupported() -> None:
    body = b"payload"
    svc, _ = service(ClamAVVerdict(completed=False, malware_match=False, error_code="unsupported_resource"))
    assert svc.scan(signed_request(body), body)["scan_record"]["result"] == "unsupported"


def test_digest_mismatch_fails_before_scan() -> None:
    body = b"payload"
    svc, scanner = service(ClamAVVerdict(completed=True, malware_match=False))
    request = signed_request(body, content_sha256="f" * 64)
    expect_error("scan_content_digest_mismatch", lambda: svc.scan(request, body))
    assert scanner.calls == 0


def test_length_mismatch_fails_before_scan() -> None:
    body = b"payload"
    svc, scanner = service(ClamAVVerdict(completed=True, malware_match=False))
    request = signed_request(body, content_length=len(body) + 1)
    expect_error("scan_content_length_mismatch", lambda: svc.scan(request, body))
    assert scanner.calls == 0


def test_bad_signature_fails_before_scan() -> None:
    body = b"payload"
    svc, scanner = service(ClamAVVerdict(completed=True, malware_match=False))
    request = replace(signed_request(body), signature="f" * 64)
    expect_error("scan_signature_invalid", lambda: svc.scan(request, body))
    assert scanner.calls == 0


def test_unknown_caller_fails_closed() -> None:
    body = b"payload"
    svc, scanner = service(ClamAVVerdict(completed=True, malware_match=False))
    request = signed_request(body, caller_id="goreecloud-browser")
    expect_error("scan_caller_not_authorized", lambda: svc.scan(request, body))
    assert scanner.calls == 0


def test_resource_type_permission_is_least_privilege() -> None:
    body = b"payload"
    svc, scanner = service(ClamAVVerdict(completed=True, malware_match=False))
    request = signed_request(body, resource_type="browser_download")
    expect_error("scan_resource_type_not_authorized", lambda: svc.scan(request, body))
    assert scanner.calls == 0


def test_timestamp_window_fails_closed() -> None:
    body = b"payload"
    svc, scanner = service(ClamAVVerdict(completed=True, malware_match=False))
    request = signed_request(body, timestamp=(NOW - timedelta(minutes=5)).isoformat())
    expect_error("scan_request_timestamp_outside_window", lambda: svc.scan(request, body))
    assert scanner.calls == 0


def test_exact_nonce_replay_returns_same_record_without_rescan() -> None:
    body = b"payload"
    svc, scanner = service(ClamAVVerdict(completed=True, malware_match=False))
    request = signed_request(body)
    first = svc.scan(request, body)
    second = svc.scan(request, body)
    assert first == second
    assert scanner.calls == 1


def test_conflicting_nonce_reuse_fails_closed() -> None:
    body = b"payload"
    svc, scanner = service(ClamAVVerdict(completed=True, malware_match=False))
    svc.scan(signed_request(body), body)
    other = b"different"
    request = signed_request(other, nonce="nonce-001", correlation_id="corr-002")
    expect_error("scan_nonce_conflict", lambda: svc.scan(request, other))
    assert scanner.calls == 1


def test_inactive_credential_fails_closed() -> None:
    body = b"payload"
    scanner = FakeScanner(ClamAVVerdict(completed=True, malware_match=False))
    inactive = replace(credential(), active=False)
    svc = AuthenticatedScanService(
        scanner=scanner,
        health_provider=health,
        credentials={(inactive.caller_id, inactive.key_id): inactive},
        now=lambda: NOW,
    )
    expect_error("scan_caller_not_authorized", lambda: svc.scan(signed_request(body), body))
    assert scanner.calls == 0


def main() -> None:
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(f"Wardveil Scan transport tests passed ({len(tests)} cases)")


if __name__ == "__main__":
    main()
