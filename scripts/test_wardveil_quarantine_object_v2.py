#!/usr/bin/env python3
"""Self-tests for the Wardveil next-upgrade Quarantine object."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))

from wardveil_quarantine_object_v2 import QuarantineObject

NOW = datetime(2026, 9, 9, 22, 0, tzinfo=timezone.utc)


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def fresh() -> QuarantineObject:
    return QuarantineObject(
        quarantine_object_id="qo-test-1",
        correlation_id="corr-test-1",
        target_authority="goreecloud-drive",
        resource_type="drive_file",
        resource_id="file-private-id",
        initiating_finding_ref="finding:malware:1",
        policy_decision_ref="policy:quarantine:1",
        related_incident_ref="incident:1",
        now=NOW,
    )


def main() -> None:
    obj = fresh()
    check(obj.state == "quarantine_pending", "new object must begin pending")
    check(obj.as_record()["reconciliation"]["original_authorization_reusable"] is False, "authorization reuse must always be false")

    obj.request_action(
        "quarantine",
        authorization_ref="auth:q:1",
        executor_id="wardveil-protect",
        idempotency_key="idem:q:1",
        evidence_refs=("policy:quarantine:1",),
        now=NOW + timedelta(seconds=1),
    )
    check(obj.state == "isolation_requested", "quarantine request must not immediately claim success")
    obj.mark_execution_started(
        evidence_ref="exec-claim:q:1",
        now=NOW + timedelta(seconds=2),
    )
    check(obj.state == "isolation_executing", "execution start must remain non-final")
    obj.complete_action(
        target_state_ref="drive-state:held:1",
        verified_resulting_state="held",
        evidence_refs=("drive-readback:1",),
        audit_ref="audit:q:1",
        now=NOW + timedelta(seconds=3),
    )
    check(obj.state == "verified_quarantined", "only verified target readback may finalize quarantine")
    record = obj.as_record()
    check(record["target_state_ref"] == "drive-state:held:1", "verified quarantine must retain target-state reference")
    check(record["verified_resulting_state"] == "held", "verified quarantine must retain resulting state")
    check("audit:q:1" in record["audit_refs"], "verified action must preserve audit provenance")

    try:
        obj.request_action(
            "delete",
            authorization_ref="auth:delete:1",
            executor_id="wardveil-protect",
            idempotency_key="idem:delete:1",
        )
    except ValueError as exc:
        check("separate_executor_contract" in str(exc), "delete must remain a separate destructive contract")
    else:
        raise AssertionError("quarantine object must not conflate delete with removal")

    obj.request_action(
        "release",
        authorization_ref="auth:release:1",
        executor_id="wardveil-protect",
        idempotency_key="idem:release:1",
        now=NOW + timedelta(seconds=4),
    )
    check(obj.state == "release_pending", "release must be separately authorized and pending")
    obj.complete_action(
        target_state_ref="drive-state:released:1",
        verified_resulting_state="released",
        evidence_refs=("drive-readback:release:1",),
        now=NOW + timedelta(seconds=5),
    )
    check(obj.state == "released", "release requires verified target result")

    uncertain = fresh()
    uncertain.request_action(
        "quarantine",
        authorization_ref="auth:q:uncertain",
        executor_id="wardveil-protect",
        idempotency_key="idem:q:uncertain",
        now=NOW + timedelta(seconds=1),
    )
    uncertain.mark_execution_started(
        evidence_ref="exec-claim:q:uncertain",
        now=NOW + timedelta(seconds=2),
    )
    uncertain.mark_uncertain(
        reason="target_acknowledgement_lost_after_possible_side_effect",
        evidence_refs=("transport-timeout:1",),
        now=NOW + timedelta(seconds=3),
    )
    check(uncertain.state == "reconciliation_required", "uncertain side effect must require reconciliation")
    check(uncertain.reconciliation_required is True, "reconciliation flag must be durable")

    try:
        uncertain.request_action(
            "quarantine",
            authorization_ref="auth:q:blind-retry",
            executor_id="wardveil-protect",
            idempotency_key="idem:q:blind-retry",
        )
    except ValueError as exc:
        check("reconciliation_must_complete" in str(exc), "new action must be blocked during reconciliation")
    else:
        raise AssertionError("uncertain side effect must never be blindly retried")

    uncertain.reconcile(
        observed_outcome="unknown",
        evidence_ref="drive-readback:still-unavailable",
        actor_id="wardveil-reconciler",
        now=NOW + timedelta(seconds=4),
    )
    check(uncertain.state == "reconciliation_required", "unknown reconciliation must preserve uncertainty")

    try:
        uncertain.reconcile(
            observed_outcome="succeeded",
            evidence_ref="drive-readback:success-no-state",
            actor_id="wardveil-reconciler",
            now=NOW + timedelta(seconds=5),
        )
    except ValueError as exc:
        check("target_state_verification" in str(exc), "success reconciliation must require authoritative target state")
    else:
        raise AssertionError("reconciliation success without target-state proof must be rejected")

    uncertain.reconcile(
        observed_outcome="succeeded",
        evidence_ref="drive-readback:success",
        actor_id="wardveil-reconciler",
        target_state_ref="drive-state:held:uncertain",
        verified_resulting_state="held",
        now=NOW + timedelta(seconds=6),
    )
    check(uncertain.state == "verified_quarantined", "verified reconciliation may establish quarantined state")
    check(uncertain.reconciliation_required is False, "resolved reconciliation must clear the active flag")
    check(uncertain.as_record()["reconciliation"]["original_authorization_reusable"] is False, "resolved reconciliation still must not reopen original authorization")

    not_executed = fresh()
    not_executed.request_action(
        "quarantine",
        authorization_ref="auth:q:not-executed",
        executor_id="wardveil-protect",
        idempotency_key="idem:q:not-executed",
        now=NOW + timedelta(seconds=1),
    )
    not_executed.mark_uncertain(
        reason="dispatch_result_unknown",
        now=NOW + timedelta(seconds=2),
    )
    not_executed.reconcile(
        observed_outcome="not_executed",
        evidence_ref="target-proof:not-executed",
        actor_id="wardveil-reconciler",
        now=NOW + timedelta(seconds=3),
    )
    check(not_executed.state == "failed", "proven not-executed action must require a new authorization before retry")
    not_executed.request_action(
        "quarantine",
        authorization_ref="auth:q:new-after-reconcile",
        executor_id="wardveil-protect",
        idempotency_key="idem:q:new-after-reconcile",
        now=NOW + timedelta(seconds=4),
    )
    check(not_executed.authorization_ref == "auth:q:new-after-reconcile", "retry after reconciliation must use a new authorization")

    rescan = fresh()
    rescan.request_action(
        "quarantine",
        authorization_ref="auth:q:rescan",
        executor_id="wardveil-protect",
        idempotency_key="idem:q:rescan",
    )
    rescan.complete_action(
        target_state_ref="drive-state:held:rescan",
        verified_resulting_state="held",
        evidence_refs=("drive-readback:held",),
    )
    rescan.request_action(
        "rescan",
        authorization_ref="auth:rescan:1",
        executor_id="wardveil-scan",
        idempotency_key="idem:rescan:1",
    )
    check(rescan.state == "rescan_pending", "rescan must be separately authorized")
    rescan.complete_action(
        target_state_ref="drive-state:held:rescan",
        verified_resulting_state="held_after_rescan",
        evidence_refs=("scan-result:1", "drive-readback:held-after-rescan"),
    )
    check(rescan.state == "verified_quarantined", "rescan completion must not silently release quarantined content")

    print("Wardveil next-upgrade Quarantine object self-tests passed.")


if __name__ == "__main__":
    main()
