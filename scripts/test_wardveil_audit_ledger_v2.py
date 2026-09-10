#!/usr/bin/env python3
"""Self-tests for the Wardveil next-upgrade Audit and Evidence Ledger."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))

from wardveil_audit_ledger_v2 import AuditLedger

NOW = datetime(2026, 9, 10, 17, 0, tzinfo=timezone.utc)


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    ledger = AuditLedger()

    decision = ledger.append(
        audit_event_id="audit-decision-1",
        correlation_id="corr-1",
        event_category="security_decision",
        producer_id="wardveil-policy",
        authority_domain="security",
        actor_id="operator-1",
        policy_id="policy-1",
        target_authority="goreecloud-drive",
        resource_type="drive_file",
        resource_id="file-private-id",
        requested_action="quarantine",
        outcome="requested",
        evidence_refs=("policy-evidence:1",),
        source_record_refs=("policy-record:1",),
        reason_code="malware_policy_requires_quarantine",
        summary="Policy requested non-destructive quarantine.",
        evidence_observed_at=NOW - timedelta(seconds=1),
        evidence_valid_until=NOW + timedelta(minutes=5),
        now=NOW,
    )
    check(decision.sequence == 1, "first audit event must start sequence at one")
    check(ledger.verify_chain(), "single-event audit chain must verify")

    try:
        ledger.append(
            audit_event_id="audit-bad-success",
            correlation_id="corr-1",
            event_category="execution",
            producer_id="wardveil-protect",
            authority_domain="security",
            service_identity_id="wardveil-protect",
            authorization_id="auth-1",
            executor_id="drive-quarantine-executor",
            target_authority="goreecloud-drive",
            resource_type="drive_file",
            resource_id="file-private-id",
            requested_action="quarantine",
            outcome="succeeded",
            evidence_refs=("executor-ack:1",),
            source_record_refs=("protect-record:1",),
            reconciliation_state="not_required",
            reason_code="executor_reported_success",
            summary="Executor acknowledged the request.",
            now=NOW + timedelta(seconds=1),
        )
    except ValueError as exc:
        check(
            "successful_execution_requires_verification_evidence" in str(exc),
            "authorization or acknowledgement alone must not prove successful execution",
        )
    else:
        raise AssertionError("successful execution was accepted without verification evidence")

    uncertain = ledger.append(
        audit_event_id="audit-execution-1",
        correlation_id="corr-1",
        event_category="execution",
        producer_id="wardveil-protect",
        authority_domain="security",
        service_identity_id="wardveil-protect",
        authorization_id="auth-1",
        executor_id="drive-quarantine-executor",
        signing_key_id="key-2026-09",
        target_authority="goreecloud-drive",
        resource_type="drive_file",
        resource_id="file-private-id",
        requested_action="quarantine",
        outcome="unknown",
        evidence_refs=("transport-timeout:1",),
        source_record_refs=("execution-claim:1",),
        reconciliation_state="required",
        incident_ref="incident-1",
        quarantine_object_ref="quarantine-1",
        reason_code="target_outcome_uncertain",
        summary="Target may have executed; authoritative readback is required.",
        now=NOW + timedelta(seconds=2),
    )
    check(
        ledger.open_reconciliation_event_ids == ("audit-execution-1",),
        "uncertain execution must remain individually attributable",
    )

    unresolved = ledger.append(
        audit_event_id="audit-reconciliation-open-1",
        correlation_id="corr-1",
        event_category="reconciliation",
        producer_id="goreecloud-drive",
        authority_domain="resource_state",
        service_identity_id="goreecloud-drive",
        target_authority="goreecloud-drive",
        resource_type="drive_file",
        resource_id="file-private-id",
        requested_action="reconcile_quarantine",
        outcome="unknown",
        evidence_refs=("drive-readback:uncertain",),
        source_record_refs=("drive-state:1",),
        reconciliation_state="required",
        reconciles_audit_event_id=uncertain.audit_event_id,
        reconciled_outcome="unknown",
        incident_ref="incident-1",
        quarantine_object_ref="quarantine-1",
        reason_code="authoritative_state_still_uncertain",
        summary="Drive could not yet prove the target state.",
        now=NOW + timedelta(seconds=3),
    )
    check(
        ledger.open_reconciliation_event_ids == ("audit-execution-1",),
        "unknown reconciliation must preserve original uncertainty",
    )
    check(unresolved.reconciled_outcome == "unknown", "unknown reconciliation outcome must be durable")

    resolved = ledger.append(
        audit_event_id="audit-reconciliation-closed-1",
        correlation_id="corr-1",
        event_category="reconciliation",
        producer_id="goreecloud-drive",
        authority_domain="resource_state",
        service_identity_id="goreecloud-drive",
        target_authority="goreecloud-drive",
        resource_type="drive_file",
        resource_id="file-private-id",
        requested_action="reconcile_quarantine",
        outcome="reconciled",
        evidence_refs=("drive-readback:held:1",),
        verification_evidence_refs=("drive-readback:held:1",),
        source_record_refs=("drive-state:2",),
        reconciliation_state="reconciled",
        reconciles_audit_event_id=uncertain.audit_event_id,
        reconciled_outcome="succeeded",
        incident_ref="incident-1",
        quarantine_object_ref="quarantine-1",
        reason_code="authoritative_target_state_verified",
        summary="Drive verified the target is held in quarantine.",
        now=NOW + timedelta(seconds=4),
    )
    check(
        ledger.open_reconciliation_event_ids == (),
        "verified reconciliation must clear only its matched uncertainty",
    )
    check(resolved.reconciles_audit_event_id == "audit-execution-1", "reconciliation must bind original audit event")

    try:
        ledger.append(
            audit_event_id="audit-reconciliation-other",
            correlation_id="corr-1",
            event_category="reconciliation",
            producer_id="goreecloud-drive",
            authority_domain="resource_state",
            service_identity_id="goreecloud-drive",
            target_authority="goreecloud-drive",
            resource_type="drive_file",
            resource_id="file-private-id",
            requested_action="reconcile_quarantine",
            outcome="reconciled",
            evidence_refs=("drive-readback:other",),
            source_record_refs=("drive-state:other",),
            reconciliation_state="reconciled",
            reconciles_audit_event_id="audit-not-open",
            reconciled_outcome="not_executed",
            reason_code="invalid_unmatched_reconciliation",
            summary="This event must be rejected.",
            now=NOW + timedelta(seconds=5),
        )
    except ValueError as exc:
        check(
            "reconciliation_does_not_match_open_uncertainty" in str(exc),
            "reconciliation must not clear unrelated uncertainty",
        )
    else:
        raise AssertionError("unmatched reconciliation was accepted")

    successful = ledger.append(
        audit_event_id="audit-execution-2",
        correlation_id="corr-2",
        event_category="execution",
        producer_id="wardveil-protect",
        authority_domain="security",
        service_identity_id="wardveil-protect",
        policy_id="policy-2",
        authorization_id="auth-2",
        executor_id="drive-quarantine-executor",
        signing_key_id="key-2026-09",
        target_authority="goreecloud-drive",
        resource_type="drive_file",
        resource_id="file-2",
        requested_action="quarantine",
        outcome="succeeded",
        evidence_refs=("protect-receipt:2",),
        verification_evidence_refs=("drive-readback:held:2",),
        source_record_refs=("execution-claim:2", "protect-receipt:2"),
        reconciliation_state="not_required",
        incident_ref="incident-2",
        quarantine_object_ref="quarantine-2",
        reason_code="verified_quarantine",
        summary="Authoritative target-state readback verified quarantine.",
        evidence_observed_at=NOW,
        evidence_valid_until=NOW + timedelta(minutes=1),
        now=NOW + timedelta(seconds=6),
    )
    explanation = ledger.explain(successful.audit_event_id, as_of=NOW + timedelta(seconds=30))
    check(explanation["outcome"] == "succeeded", "Security Center explanation must preserve execution outcome")
    check(explanation["evidence_freshness"] == "current", "current evidence must be labeled current")
    expired = ledger.explain(successful.audit_event_id, as_of=NOW + timedelta(minutes=2))
    check(
        expired["evidence_freshness"] == "expired",
        "expired evidence may remain historical but must not present as current",
    )

    try:
        ledger.append(
            audit_event_id="audit-sensitive",
            correlation_id="corr-sensitive",
            event_category="security_observation",
            producer_id="wardveil-audit",
            authority_domain="security",
            actor_id="operator-1",
            target_authority="wardveil",
            resource_type="service",
            resource_id="wardveil-audit",
            requested_action="observe",
            outcome="succeeded",
            evidence_refs=("evidence:1",),
            source_record_refs=("record:1",),
            reason_code="sensitive_test",
            summary="Authorization: Bearer example-reusable-value",
            now=NOW + timedelta(seconds=7),
        )
    except ValueError as exc:
        check(
            "contains_prohibited_sensitive_material" in str(exc),
            "audit summaries must reject obvious reusable secret material",
        )
    else:
        raise AssertionError("audit ledger accepted obvious credential material")

    check(ledger.verify_chain(), "complete audit chain must verify")
    tampered = replace(ledger.events[-1], summary="Tampered summary.")
    original = ledger._events[-1]
    ledger._events[-1] = tampered
    check(not ledger.verify_chain(), "hash-linked ledger must detect event mutation")
    ledger._events[-1] = original
    check(ledger.verify_chain(), "restored audit chain must verify")

    record = successful.as_record()
    check(record["retention"]["class"] == "audit_evidence", "audit retention class must be explicit")
    check(record["retention"]["purpose"] == "security_provenance", "audit purpose limitation must be explicit")
    check(record["retention"]["may_leave_origin"] is False, "audit evidence must default to origin-local retention")
    check("event_hash" in record, "audit event must carry integrity hash")
    check("previous_event_hash" in record, "later audit events must carry prior hash")

    print("Wardveil next-upgrade Audit and Evidence Ledger self-tests passed.")


if __name__ == "__main__":
    main()
