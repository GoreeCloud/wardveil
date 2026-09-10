#!/usr/bin/env python3
"""Self-tests for the Wardveil next-upgrade Incident Plane."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))

from wardveil_incident_v2 import Incident

NOW = datetime(2026, 9, 10, 5, 0, tzinfo=timezone.utc)


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def fresh() -> Incident:
    return Incident(
        incident_id="incident-test-1",
        correlation_id="corr-test-1",
        severity="high",
        target_authority="goreecloud-drive",
        resource_type="drive_file",
        resource_id="file-private-id",
        initiating_evidence_refs=("finding:malware:1",),
        source_record_refs=("wardveil-finding:1",),
        now=NOW,
    )


def main() -> None:
    incident = fresh()
    check(incident.state == "open", "incident must begin open")
    check(incident.as_record()["transitions"][0]["to_state"] == "open", "creation transition must be recorded")

    incident.add_timeline_event(
        event_type="finding",
        producer_id="wardveil-detect",
        authority_domain="security",
        summary="Malicious-content finding opened the incident.",
        evidence_refs=("finding:malware:1",),
        source_record_refs=("wardveil-finding:1",),
        now=NOW + timedelta(seconds=1),
    )
    incident.transition(
        "investigating",
        actor_id="wardveil-response",
        reason="triage_started",
        evidence_refs=("triage:1",),
        now=NOW + timedelta(seconds=2),
    )
    incident.transition(
        "containment_pending",
        actor_id="wardveil-response",
        reason="quarantine_required",
        evidence_refs=("policy:contain:1",),
        now=NOW + timedelta(seconds=3),
    )
    incident.add_timeline_event(
        event_type="quarantine",
        producer_id="wardveil-protect",
        authority_domain="security",
        summary="Quarantine was requested; target state is not yet verified.",
        evidence_refs=("auth:quarantine:1",),
        execution_state="requested",
        quarantine_object_ref="quarantine:1",
        now=NOW + timedelta(seconds=4),
    )
    incident.add_timeline_event(
        event_type="quarantine",
        producer_id="goreecloud-drive",
        authority_domain="resource_state",
        summary="Drive target readback verified isolated state.",
        evidence_refs=("drive-readback:held:1",),
        execution_state="verified",
        quarantine_object_ref="quarantine:1",
        now=NOW + timedelta(seconds=5),
    )
    incident.transition(
        "contained",
        actor_id="wardveil-response",
        reason="authoritative_target_state_verified",
        evidence_refs=("drive-readback:held:1",),
        now=NOW + timedelta(seconds=6),
    )

    incident.transition(
        "recovery_pending",
        actor_id="wardveil-response",
        reason="recovery_required_after_containment",
        evidence_refs=("recovery-plan:1",),
        now=NOW + timedelta(seconds=7),
    )
    try:
        incident.transition(
            "recovering",
            actor_id="wardveil-response",
            reason="start_recovery",
            evidence_refs=("recovery-plan:1",),
        )
    except ValueError as exc:
        check("recovery_reference" in str(exc), "recovering must require a concrete recovery reference")
    else:
        raise AssertionError("recovering must fail without recovery reference")

    incident.add_timeline_event(
        event_type="recovery_action",
        producer_id="everkeep",
        authority_domain="recovery",
        summary="Everkeep recovery operation was accepted for the contained target.",
        evidence_refs=("everkeep-plan:1",),
        execution_state="requested",
        recovery_ref="everkeep-recovery:1",
        now=NOW + timedelta(seconds=8),
    )
    incident.transition(
        "recovering",
        actor_id="wardveil-response",
        reason="recovery_operation_in_progress",
        evidence_refs=("everkeep-plan:1",),
        now=NOW + timedelta(seconds=9),
    )
    incident.add_timeline_event(
        event_type="everkeep_recovery_evidence",
        producer_id="everkeep",
        authority_domain="recovery",
        summary="Everkeep verified the restored recovery result.",
        evidence_refs=("everkeep-recovery-evidence:1",),
        execution_state="verified",
        recovery_ref="everkeep-recovery:1",
        now=NOW + timedelta(seconds=10),
    )
    incident.transition(
        "verification_pending",
        actor_id="wardveil-response",
        reason="recovery_complete_security_verification_required",
        evidence_refs=("everkeep-recovery-evidence:1",),
        now=NOW + timedelta(seconds=11),
    )

    try:
        incident.transition(
            "resolved",
            actor_id="wardveil-response",
            reason="attempt_resolution_without_wardveil_verification",
            evidence_refs=("resolution-review:1",),
            final_outcome="contained_and_recovered",
            resolution_evidence_refs=("resolution-review:1",),
        )
    except ValueError as exc:
        check("wardveil_verification" in str(exc), "recovery-linked resolution must require Wardveil verification")
    else:
        raise AssertionError("recovery-linked incident resolved without Wardveil verification")

    incident.add_timeline_event(
        event_type="wardveil_recovery_verification",
        producer_id="wardveil-protect",
        authority_domain="security",
        summary="Wardveil independently verified the restored target for normal operation.",
        evidence_refs=("wardveil-recovery-verification:1",),
        execution_state="verified",
        recovery_ref="everkeep-recovery:1",
        now=NOW + timedelta(seconds=12),
    )
    incident.transition(
        "resolved",
        actor_id="wardveil-response",
        reason="containment_recovery_and_security_verification_complete",
        evidence_refs=("wardveil-recovery-verification:1",),
        final_outcome="contained_recovered_and_verified",
        resolution_evidence_refs=("resolution-evidence:1",),
        now=NOW + timedelta(seconds=13),
    )
    record = incident.as_record()
    check(record["state"] == "resolved", "incident should resolve after full evidence chain")
    check(record["resolution"]["final_outcome"] == "contained_recovered_and_verified", "final outcome must be durable")
    check(record["everkeep_evidence_refs"], "Everkeep evidence must remain linked")
    check(record["wardveil_recovery_verification_refs"], "Wardveil recovery verification must remain linked")
    check(record["timeline"][2]["execution_state"] == "verified", "timeline must distinguish verified action outcome")

    incident.transition(
        "archived",
        actor_id="wardveil-security-operations",
        reason="resolved_incident_retention_transition",
        evidence_refs=("archive-policy:1",),
        now=NOW + timedelta(seconds=14),
    )
    try:
        incident.add_timeline_event(
            event_type="resolution",
            producer_id="wardveil-response",
            authority_domain="security",
            summary="Invalid mutation after archive.",
            evidence_refs=("bad:1",),
        )
    except ValueError as exc:
        check("immutable" in str(exc), "archived incident timeline must be immutable")
    else:
        raise AssertionError("archived incident accepted timeline mutation")

    uncertain = fresh()
    uncertain.transition(
        "investigating",
        actor_id="wardveil-response",
        reason="investigation_started",
        evidence_refs=("triage:uncertain",),
    )
    uncertain.transition(
        "containment_pending",
        actor_id="wardveil-response",
        reason="containment_required",
        evidence_refs=("policy:uncertain",),
    )
    uncertain.add_timeline_event(
        event_type="protection_action",
        producer_id="wardveil-protect",
        authority_domain="security",
        summary="Containment may have executed but acknowledgement was lost.",
        evidence_refs=("transport-timeout:1",),
        execution_state="uncertain",
        source_record_refs=("execution:1",),
    )
    try:
        uncertain.transition(
            "contained",
            actor_id="wardveil-response",
            reason="invalid_containment_upgrade",
            evidence_refs=("transport-timeout:1",),
        )
    except ValueError as exc:
        check("reconciliation_must_complete" in str(exc), "uncertainty must block stronger incident state")
    else:
        raise AssertionError("uncertain execution incorrectly upgraded incident to contained")

    uncertain.add_timeline_event(
        event_type="reconciliation",
        producer_id="goreecloud-drive",
        authority_domain="resource_state",
        summary="Authoritative target readback established containment.",
        evidence_refs=("drive-readback:contained:1",),
        execution_state="verified",
        source_record_refs=("execution:1",),
    )
    uncertain.transition(
        "contained",
        actor_id="wardveil-response",
        reason="reconciliation_verified_containment",
        evidence_refs=("drive-readback:contained:1",),
    )
    check(uncertain.state == "contained", "verified reconciliation may permit state advancement")

    try:
        fresh().add_timeline_event(
            event_type="quarantine",
            producer_id="wardveil-protect",
            authority_domain="security",
            summary="Missing explicit execution state.",
            evidence_refs=("event:1",),
        )
    except ValueError as exc:
        check("execution_state" in str(exc), "security action timeline event must label execution state")
    else:
        raise AssertionError("security action event omitted execution state")

    print("Wardveil next-upgrade Incident Plane self-tests passed.")


if __name__ == "__main__":
    main()
