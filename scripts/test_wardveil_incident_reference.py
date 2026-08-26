#!/usr/bin/env python3
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_incident import (  # noqa: E402
    Authority,
    Scope,
    append_audit_event,
    create_incident,
    quarantine,
    transition_incident,
    transition_quarantine,
    verify_audit_chain,
)

NOW = datetime(2026, 8, 26, 15, 0, tzinfo=timezone.utc)
SCOPE = Scope("file", "file-123", "open", "user")
FULL = Authority("wardveil-response-reference", frozenset({
    "quarantine", "review_quarantine", "release_quarantine", "remove_quarantined_content",
    "contain_incident", "remediate_incident", "coordinate_recovery", "verify_recovery", "close_incident",
}))


def expect_raises(exc, fn, message):
    try:
        fn()
    except exc:
        return
    raise AssertionError(message)


def test_quarantine_is_not_deletion():
    record = quarantine(
        record_id="q-1", correlation_id="c-1", producer_id="wardveil-quarantine-reference",
        scope=SCOPE, reason="malicious scan finding", evidence_refs=("evidence:scan",),
        source_record_ids=("scan-1",), authority=FULL, now=NOW,
    )
    assert record.review_state == "pending"
    assert record.destructive_action is False


def test_release_requires_explicit_authority():
    record = quarantine(
        record_id="q-2", correlation_id="c-2", producer_id="wardveil-quarantine-reference",
        scope=SCOPE, reason="suspicious", evidence_refs=("evidence:scan",),
        source_record_ids=("scan-2",), authority=FULL, now=NOW,
    )
    expect_raises(PermissionError, lambda: transition_quarantine(record, "released", Authority("viewer", frozenset())), "release must require authority")
    released = transition_quarantine(record, "released", FULL)
    assert released.review_state == "released"
    assert released.destructive_action is False


def test_removal_is_explicit_destructive_action():
    record = quarantine(
        record_id="q-3", correlation_id="c-3", producer_id="wardveil-quarantine-reference",
        scope=SCOPE, reason="confirmed malware", evidence_refs=("evidence:malware",),
        source_record_ids=("detect-1",), authority=FULL, now=NOW,
    )
    removed = transition_quarantine(record, "removed", FULL)
    assert removed.destructive_action is True


def test_audit_chain_detects_tampering():
    first = append_audit_event(
        record_id="a-1", correlation_id="c-4", producer_id="wardveil-audit-reference",
        scope=SCOPE, event_type="quarantine.created", outcome="success", actor_id="wardveil-quarantine-reference",
        evidence_refs=("evidence:q",), now=NOW,
    )
    second = append_audit_event(
        record_id="a-2", correlation_id="c-4", producer_id="wardveil-audit-reference",
        scope=SCOPE, event_type="incident.opened", outcome="success", actor_id="wardveil-response-reference",
        evidence_refs=("evidence:i",), previous=first, now=NOW,
    )
    assert verify_audit_chain((first, second))
    tampered = second.__class__(**{**second.__dict__, "event_type": "incident.closed"})
    assert not verify_audit_chain((first, tampered))


def test_incident_transitions_are_ordered_and_authorized():
    incident = create_incident(
        record_id="i-1", correlation_id="c-5", producer_id="wardveil-response-reference",
        scope=SCOPE, severity="high", evidence_refs=("evidence:incident",), source_record_ids=("detect-2",), now=NOW,
    )
    expect_raises(ValueError, lambda: transition_incident(incident, "remediating", authority=FULL), "must not skip containment")
    contained = transition_incident(incident, "contained", authority=FULL, response_action="revoke_session")
    assert contained.incident_status == "contained"
    assert contained.response_actions == ("revoke_session",)


def test_everkeep_recovery_boundary():
    incident = create_incident(
        record_id="i-2", correlation_id="c-6", producer_id="wardveil-response-reference",
        scope=SCOPE, severity="critical", evidence_refs=("evidence:ransomware",), source_record_ids=("detect-3",), now=NOW,
    )
    contained = transition_incident(incident, "contained", authority=FULL)
    remediating = transition_incident(contained, "remediating", authority=FULL)
    expect_raises(ValueError, lambda: transition_incident(remediating, "recovering", authority=FULL), "recovery must be explicitly requested")
    recovering = transition_incident(remediating, "recovering", authority=FULL, everkeep_recovery_requested=True)
    expect_raises(ValueError, lambda: transition_incident(recovering, "verified", authority=FULL), "recovery must be verified before Wardveil verifies incident")
    verified = transition_incident(recovering, "verified", authority=FULL, everkeep_recovery_verified=True)
    closed = transition_incident(verified, "closed", authority=FULL)
    assert closed.incident_status == "closed"


def test_runtime_record_types():
    q = quarantine(
        record_id="q-4", correlation_id="c-7", producer_id="wardveil-quarantine-reference",
        scope=SCOPE, reason="test", evidence_refs=("evidence:test",), source_record_ids=("scan-4",), authority=FULL, now=NOW,
    )
    assert q.as_runtime_record()["record_type"] == "quarantine_record"
    i = create_incident(
        record_id="i-3", correlation_id="c-7", producer_id="wardveil-response-reference",
        scope=SCOPE, severity="medium", evidence_refs=("evidence:test",), source_record_ids=("detect-4",), now=NOW,
    )
    assert i.as_runtime_record()["record_type"] == "incident_record"
    a = append_audit_event(
        record_id="a-3", correlation_id="c-7", producer_id="wardveil-audit-reference",
        scope=SCOPE, event_type="test", outcome="success", actor_id="tester", evidence_refs=("evidence:test",), now=NOW,
    )
    assert a.as_runtime_record()["record_type"] == "audit_event"


def main():
    tests = [name for name, value in globals().items() if name.startswith("test_") and callable(value)]
    for name in sorted(tests):
        globals()[name]()
    print(f"Wardveil Quarantine + Audit + Response reference tests passed: {len(tests)}")


if __name__ == "__main__":
    main()
