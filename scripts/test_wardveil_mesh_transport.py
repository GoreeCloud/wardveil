#!/usr/bin/env python3
from __future__ import annotations

import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from reference.wardveil_mesh_transport import ConsumerPolicy, ReplayLedger, create_envelope, verify_and_accept

NOW = datetime(2026, 8, 26, 10, 20, tzinfo=timezone.utc)
KEY = b"wardveil-reference-test-key-not-production"


def record(record_type: str = "scan_finding", *, valid: bool = True) -> dict:
    data = {
        "contract_version": "0.1.0",
        "record_type": record_type,
        "record_id": "scan-1",
        "correlation_id": "corr-1",
        "producer": {"id": "wardveil-scan-reference", "authoritative": True},
        "scope": {"resource_type": "file", "resource_id": "file-1"},
        "observed_at": NOW.isoformat(),
        "evidence_refs": ["evidence:scan-1"],
        "scan_result": "clean",
    }
    if valid:
        data["valid_until"] = (NOW + timedelta(minutes=10)).isoformat()
    return data


def main() -> None:
    consumer = ConsumerPolicy("security-center", frozenset({"scan_finding", "audit_event"}), frozenset({"file"}))
    ledger = ReplayLedger()

    envelope = create_envelope(record(), signing_key=KEY, audience=("security-center",), replay_key="rk-1", now=NOW)
    accepted = verify_and_accept(envelope, signing_key=KEY, consumer=consumer, replay_ledger=ledger, now=NOW)
    assert accepted["accepted"] is True
    assert accepted["delivery_authority_transferred"] is False

    repeated = verify_and_accept(envelope, signing_key=KEY, consumer=consumer, replay_ledger=ledger, now=NOW)
    assert repeated["accepted"] is True

    envelope2 = create_envelope(record(), signing_key=KEY, audience=("security-center",), replay_key="rk-1", now=NOW)
    conflict = verify_and_accept(envelope2, signing_key=KEY, consumer=consumer, replay_ledger=ledger, now=NOW)
    assert conflict == {"accepted": False, "reason": "replay_key_conflict"}

    tampered = replace(envelope, record={**envelope.record, "scan_result": "malicious"})
    rejected = verify_and_accept(tampered, signing_key=KEY, consumer=consumer, replay_ledger=ReplayLedger(), now=NOW)
    assert rejected == {"accepted": False, "reason": "payload_digest_mismatch"}

    unauthorized = ConsumerPolicy("other-service", frozenset({"scan_finding"}), frozenset({"file"}))
    denied = verify_and_accept(envelope, signing_key=KEY, consumer=unauthorized, replay_ledger=ReplayLedger(), now=NOW)
    assert denied == {"accepted": False, "reason": "consumer_not_in_audience"}

    expired_record = record()
    expired_record["valid_until"] = (NOW - timedelta(seconds=1)).isoformat()
    try:
        create_envelope(expired_record, signing_key=KEY, audience=("security-center",), replay_key="rk-expired", now=NOW)
    except ValueError as exc:
        assert str(exc) == "expired_security_evidence"
    else:
        raise AssertionError("expired evidence must fail closed")

    audit = record("audit_event", valid=False)
    audit.update({"record_id": "audit-1", "event_type": "scan.completed", "outcome": "recorded", "actor_id": "wardveil"})
    audit_envelope = create_envelope(audit, signing_key=KEY, audience=("security-center",), replay_key="rk-audit", retention_class="audit_evidence", now=NOW)
    assert audit_envelope.expires_at == (NOW + timedelta(minutes=5)).isoformat()
    audit_result = verify_and_accept(audit_envelope, signing_key=KEY, consumer=consumer, replay_ledger=ReplayLedger(), now=NOW)
    assert audit_result["accepted"] is True

    print("Wardveil Mesh transport reference tests passed")


if __name__ == "__main__":
    main()
