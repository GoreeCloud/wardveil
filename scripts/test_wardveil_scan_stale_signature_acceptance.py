#!/usr/bin/env python3
"""Regression tests for controlled stale-signature target acceptance."""

from __future__ import annotations

import hashlib
import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path

from reference.wardveil_clamav import ClamAVConfig, ClamAVVerdict
from reference.wardveil_clamav_runtime import ClamAVRuntimePolicy

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "accept_wardveil_scan_stale_signature.py"
SPEC = importlib.util.spec_from_file_location("stale_signature_acceptance", SCRIPT)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class FakeClamAVClient:
    def __init__(self) -> None:
        self.config = ClamAVConfig(
            unix_socket=None,
            tcp_host="127.0.0.1",
            tcp_port=3310,
            timeout_seconds=1,
        )

    def ping(self) -> bool:
        return True

    def version(self) -> str:
        return "ClamAV 1.4.6/28106/Sun Aug 30 12:00:00 2026"

    def scan_bytes(self, data: bytes) -> ClamAVVerdict:
        digest = hashlib.sha256(data).hexdigest()
        if b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in data:
            return ClamAVVerdict(
                completed=True,
                malware_match=True,
                signature="Win.Test.EICAR_HDB-1",
                raw_reply="stream: Win.Test.EICAR_HDB-1 FOUND",
                digest_sha256=digest,
            )
        return ClamAVVerdict(
            completed=True,
            malware_match=False,
            raw_reply="stream: OK",
            digest_sha256=digest,
        )


def main() -> int:
    client = FakeClamAVClient()
    policy = ClamAVRuntimePolicy(
        max_signature_age=timedelta(hours=48),
        health_validity=timedelta(minutes=5),
    )
    baseline = datetime(2026, 8, 31, 10, 0, tzinfo=timezone.utc)
    recovery = datetime(2026, 8, 31, 10, 1, tzinfo=timezone.utc)

    result = module.exercise_signature_freshness(
        client,
        policy,
        baseline_now=baseline,
        recovery_now=recovery,
    )

    assert result["baseline_health"].signature_freshness == "current"
    assert result["baseline_clean"]["scan_record"]["result"] == "clean"

    assert result["stale_health"].signature_freshness == "stale"
    assert result["stale_health"].runtime_state == "degraded"
    assert "signature_database_stale" in result["stale_health"].degraded_reasons
    assert result["stale_health"].clean_verdicts_eligible is False
    assert result["stale_clean"]["scan_record"]["result"] == "unknown"
    assert result["stale_eicar"]["scan_record"]["result"] == "malicious"

    assert result["recovery_health"].signature_freshness == "current"
    assert result["recovery_health"].clean_verdicts_eligible is True
    assert result["recovery_clean"]["scan_record"]["result"] == "clean"

    assert result["stale_now"] > (
        result["baseline_health"].database_updated_at + policy.max_signature_age
    )

    print("Wardveil Scan stale-signature acceptance helper tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
