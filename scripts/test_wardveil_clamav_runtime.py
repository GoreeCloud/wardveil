#!/usr/bin/env python3
"""Dependency-free tests for Wardveil ClamAV runtime health and verdict gating."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_clamav import ClamAVConfig, ClamAVVerdict  # noqa: E402
from reference.wardveil_clamav_runtime import (  # noqa: E402
    ClamAVRuntimeMetrics,
    collect_clamav_health,
    gate_clamav_verdict,
    parse_version_reply,
)

NOW = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)


class FakeClient:
    def __init__(self, *, ping=True, version=None, exc=None):
        self.config = ClamAVConfig(
            unix_socket="/run/clamav/clamd.ctl",
            max_stream_bytes=1024,
        )
        self._ping = ping
        self._version = version or "ClamAV 1.4.6/27890/Thu Aug 27 10:00:00 2026"
        self._exc = exc

    def ping(self):
        if self._exc:
            raise self._exc
        return self._ping

    def version(self):
        if self._exc:
            raise self._exc
        return self._version


def test_version_parser():
    version = parse_version_reply("ClamAV 1.4.6/27890/Thu Aug 27 10:00:00 2026")
    assert version.engine_version == "1.4.6"
    assert version.database_version == "27890"
    assert version.database_updated_at == datetime(2026, 8, 27, 10, 0, tzinfo=timezone.utc)


def test_recent_signatures_are_healthy():
    health = collect_clamav_health(FakeClient(), now=NOW)
    assert health.runtime_state == "healthy"
    assert health.clean_verdicts_eligible
    status = health.as_status_record()
    assert status["state"] == "protected"
    assert status["scope"]["id"] == "wardveil-clamav-runtime"
    assert status["claim"]["protected_by_wardveil"] is False


def test_stale_signatures_downgrade_clean():
    client = FakeClient(version="ClamAV 1.4.6/27870/Mon Aug 24 10:00:00 2026")
    health = collect_clamav_health(client, now=NOW)
    assert health.runtime_state == "degraded"
    assert health.signature_freshness == "stale"
    verdict = ClamAVVerdict(True, False, digest_sha256="abc")
    finding = gate_clamav_verdict(verdict, health, resource_id="file-1", now=NOW)
    assert finding.result == "unknown"
    assert "scanner_health_not_acceptable_for_clean_verdict" in finding.reason_codes


def test_malware_match_survives_stale_health():
    client = FakeClient(version="ClamAV 1.4.6/27870/Mon Aug 24 10:00:00 2026")
    health = collect_clamav_health(client, now=NOW)
    verdict = ClamAVVerdict(
        True,
        True,
        signature="Unit-Test-Signature",
        digest_sha256="def",
    )
    finding = gate_clamav_verdict(verdict, health, resource_id="file-2", now=NOW)
    assert finding.result == "malicious"


def test_unreachable_is_unknown_status():
    health = collect_clamav_health(FakeClient(ping=False), now=NOW)
    assert health.runtime_state == "unavailable"
    assert not health.clean_verdicts_eligible
    status = health.as_status_record()
    assert status["state"] == "unknown"
    assert status["evidence"]["status"] == "unavailable"


def test_expired_healthy_evidence_downgrades_clean():
    health = collect_clamav_health(FakeClient(), now=NOW)
    verdict = ClamAVVerdict(True, False, digest_sha256="expired")
    later = NOW + timedelta(minutes=6)
    finding = gate_clamav_verdict(
        verdict,
        health,
        resource_id="file-expired",
        now=later,
    )
    assert finding.result == "unknown"
    assert "scanner_health:scanner_health_evidence_expired" in finding.reason_codes


def test_high_error_rate_degrades():
    metrics = ClamAVRuntimeMetrics(
        total_scans=20,
        scan_errors=2,
        last_successful_scan_at=NOW - timedelta(minutes=1),
    )
    health = collect_clamav_health(FakeClient(), metrics=metrics, now=NOW)
    assert health.runtime_state == "degraded"
    assert "scan_error_rate_high" in health.degraded_reasons


def main():
    tests = [name for name, value in globals().items() if name.startswith("test_") and callable(value)]
    for name in sorted(tests):
        globals()[name]()
    print(f"Wardveil ClamAV runtime health tests passed: {len(tests)}")


if __name__ == "__main__":
    main()
