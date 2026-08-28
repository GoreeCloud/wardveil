#!/usr/bin/env python3
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_security_center import build_snapshot  # noqa:E402

NOW = datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)


def rec(record_type, **extra):
    base = {
        "contract_version": "0.1.0",
        "record_type": record_type,
        "record_id": f"{record_type}-1",
        "producer": {"id": "wardveil", "authoritative": True},
        "scope": {"resource_type": "file", "resource_id": "x"},
        "observed_at": "2026-08-26T11:00:00Z",
        "evidence_refs": ["e:1"],
    }
    base.update(extra)
    return base


def main():
    snapshot = build_snapshot([], now=NOW)
    assert snapshot.protection_status == "unknown"

    snapshot = build_snapshot([rec("scan_finding", scan_result="unsupported")], now=NOW)
    assert snapshot.protection_status == "degraded" and "scan_coverage_incomplete" in snapshot.degraded_reasons

    snapshot = build_snapshot([
        rec("detection_finding", detection_disposition="confirmed_malicious", severity="high", confidence=.99)
    ], now=NOW)
    assert snapshot.protection_status == "attention" and snapshot.active_threats == 1

    snapshot = build_snapshot([
        rec(
            "protection_action", policy_decision="block", executor="wardveil-protect",
            idempotency_key="i", execution_status="succeeded", valid_until="2026-08-26T13:00:00Z",
        )
    ], now=NOW)
    assert snapshot.protection_status == "protected"

    unauth = rec("protection_action", execution_status="succeeded")
    unauth["producer"]["authoritative"] = False
    snapshot = build_snapshot([unauth], now=NOW)
    assert snapshot.protection_status == "unknown"

    snapshot = build_snapshot([
        rec("quarantine_record", review_state="pending"),
        rec("incident_record", incident_status="open", severity="critical"),
    ], now=NOW)
    assert snapshot.quarantined_items == 1 and snapshot.open_incidents == 1 and snapshot.protection_status == "attention"

    provenance = {
        "authorization_id": "authz-1",
        "issuer_id": "wardveil-policy-runtime",
        "executor_id": "wardveil-quarantine-executor-runtime",
        "signing_key_id": "wardveil-auth-current",
        "signature_algorithm": "HMAC-SHA256-reference-only",
    }
    snapshot = build_snapshot([
        rec("audit_event", event_type="quarantine.execution", outcome="success", authorization_provenance=provenance)
    ], now=NOW)
    assert snapshot.protection_status == "operational"
    assert snapshot.execution_provenance == ({key: provenance[key] for key in sorted(provenance)},)

    unsafe = dict(provenance)
    unsafe["secret"] = "must-not-surface"
    snapshot = build_snapshot([
        rec("audit_event", event_type="quarantine.execution", outcome="success", authorization_provenance=unsafe)
    ], now=NOW)
    assert snapshot.execution_provenance == ()

    print("Wardveil Security Center tests passed: 8")


if __name__ == "__main__":
    main()
