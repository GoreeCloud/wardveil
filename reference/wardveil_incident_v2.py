#!/usr/bin/env python3
"""Wardveil next-upgrade incident-plane reference model.

This module is a source-level record/state model only. It does not execute
containment, quarantine, credential revocation, recovery, or production
mutations. It preserves evidence provenance and uncertainty so Security Center
can explain an incident without treating transport, requests, or missing
events as verified outcomes.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable
from uuid import uuid4

CONTRACT_VERSION = "0.1.0"

INCIDENT_STATES = (
    "open",
    "investigating",
    "containment_pending",
    "contained",
    "recovery_pending",
    "recovering",
    "verification_pending",
    "resolved",
    "archived",
)

SEVERITIES = ("informational", "low", "medium", "high", "critical")

TIMELINE_EVENT_TYPES = (
    "finding",
    "threat_detection",
    "trust_change",
    "policy_decision",
    "execution_authorization",
    "protection_action",
    "quarantine",
    "reconciliation",
    "recovery_action",
    "everkeep_recovery_evidence",
    "wardveil_recovery_verification",
    "resolution",
)

EXECUTION_STATES = (
    "not_applicable",
    "requested",
    "executing",
    "verified",
    "failed",
    "uncertain",
)

CONTAINMENT_EVENT_TYPES = {"protection_action", "quarantine"}

ALLOWED_TRANSITIONS = {
    "open": {"investigating"},
    "investigating": {"containment_pending", "recovery_pending", "verification_pending"},
    "containment_pending": {"contained"},
    "contained": {"recovery_pending", "verification_pending"},
    "recovery_pending": {"recovering"},
    "recovering": {"verification_pending"},
    "verification_pending": {"resolved"},
    "resolved": {"archived"},
    "archived": set(),
}


def _utc(value: datetime | None = None) -> datetime:
    value = value or datetime.now(timezone.utc)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp_must_be_timezone_aware")
    return value.astimezone(timezone.utc)


def _text(value: str, field: str, max_length: int = 256) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise ValueError(f"{field}_required")
    if len(normalized) > max_length:
        raise ValueError(f"{field}_too_long")
    return normalized


def _optional_text(value: str | None, field: str, max_length: int = 256) -> str | None:
    if value is None:
        return None
    return _text(value, field, max_length)


def _refs(values: Iterable[str], *, field: str = "evidence_refs", max_items: int = 64) -> tuple[str, ...]:
    normalized = tuple(dict.fromkeys(str(value).strip() for value in values if str(value).strip()))
    if len(normalized) > max_items:
        raise ValueError(f"{field}_too_many")
    if any(len(value) > 256 for value in normalized):
        raise ValueError(f"{field}_item_too_long")
    return normalized


@dataclass(frozen=True)
class IncidentTimelineEvent:
    sequence: int
    event_type: str
    producer_id: str
    authority_domain: str
    observed_at: datetime
    summary: str
    evidence_refs: tuple[str, ...]
    execution_state: str
    source_record_refs: tuple[str, ...] = ()
    quarantine_object_ref: str | None = None
    recovery_ref: str | None = None

    def as_record(self) -> dict:
        return {
            "sequence": self.sequence,
            "event_type": self.event_type,
            "producer": {
                "id": self.producer_id,
                "authority_domain": self.authority_domain,
            },
            "observed_at": self.observed_at.isoformat(),
            "summary": self.summary,
            "evidence_refs": list(self.evidence_refs),
            "source_record_refs": list(self.source_record_refs),
            "execution_state": self.execution_state,
            **(
                {"quarantine_object_ref": self.quarantine_object_ref}
                if self.quarantine_object_ref
                else {}
            ),
            **({"recovery_ref": self.recovery_ref} if self.recovery_ref else {}),
        }


@dataclass(frozen=True)
class IncidentTransition:
    sequence: int
    from_state: str | None
    to_state: str
    observed_at: datetime
    reason: str
    actor_id: str
    evidence_refs: tuple[str, ...]

    def as_record(self) -> dict:
        return {
            "sequence": self.sequence,
            "from_state": self.from_state,
            "to_state": self.to_state,
            "observed_at": self.observed_at.isoformat(),
            "reason": self.reason,
            "actor_id": self.actor_id,
            "evidence_refs": list(self.evidence_refs),
        }


class Incident:
    """Serializable reference state for one Wardveil incident."""

    def __init__(
        self,
        *,
        correlation_id: str,
        severity: str,
        target_authority: str,
        resource_type: str,
        resource_id: str,
        initiating_evidence_refs: Iterable[str],
        source_record_refs: Iterable[str],
        incident_id: str | None = None,
        owner_role: str = "wardveil-security-operations",
        now: datetime | None = None,
    ) -> None:
        if severity not in SEVERITIES:
            raise ValueError("unsupported_incident_severity")

        evidence = _refs(initiating_evidence_refs, field="initiating_evidence_refs")
        sources = _refs(source_record_refs, field="source_record_refs")
        if not evidence:
            raise ValueError("incident_requires_initiating_evidence")
        if not sources:
            raise ValueError("incident_requires_source_records")

        self.incident_id = _text(incident_id or f"incident-{uuid4()}", "incident_id", 160)
        self.correlation_id = _text(correlation_id, "correlation_id", 160)
        self.severity = severity
        self.target_authority = _text(target_authority, "target_authority", 128)
        self.resource_type = _text(resource_type, "resource_type", 128)
        self.resource_id = _text(resource_id, "resource_id", 256)
        self.owner_role = _text(owner_role, "owner_role", 128)
        self.state = "open"
        self.initiating_evidence_refs = evidence
        self.source_record_refs = sources
        self.quarantine_object_refs: list[str] = []
        self.recovery_refs: list[str] = []
        self.everkeep_evidence_refs: list[str] = []
        self.wardveil_recovery_verification_refs: list[str] = []
        self.open_reconciliation_refs: list[str] = []
        self.resolution_evidence_refs: list[str] = []
        self.final_outcome: str | None = None
        self.timeline: list[IncidentTimelineEvent] = []
        self.transitions: list[IncidentTransition] = []
        self._append_transition(
            from_state=None,
            to_state="open",
            actor_id="wardveil-incident-plane",
            reason="incident_created_from_authoritative_security_evidence",
            evidence_refs=evidence,
            now=now,
        )

    @property
    def reconciliation_open(self) -> bool:
        return bool(self.open_reconciliation_refs)

    def _append_transition(
        self,
        *,
        from_state: str | None,
        to_state: str,
        actor_id: str,
        reason: str,
        evidence_refs: Iterable[str],
        now: datetime | None = None,
    ) -> None:
        refs = _refs(evidence_refs)
        if not refs:
            raise ValueError("incident_transition_requires_evidence")
        self.transitions.append(
            IncidentTransition(
                sequence=len(self.transitions) + 1,
                from_state=from_state,
                to_state=to_state,
                observed_at=_utc(now),
                reason=_text(reason, "transition_reason"),
                actor_id=_text(actor_id, "actor_id", 128),
                evidence_refs=refs,
            )
        )
        self.state = to_state

    def _has_verified_containment(self) -> bool:
        return any(
            event.event_type in CONTAINMENT_EVENT_TYPES
            and event.execution_state == "verified"
            for event in self.timeline
        )

    def add_timeline_event(
        self,
        *,
        event_type: str,
        producer_id: str,
        authority_domain: str,
        summary: str,
        evidence_refs: Iterable[str],
        execution_state: str = "not_applicable",
        source_record_refs: Iterable[str] = (),
        quarantine_object_ref: str | None = None,
        recovery_ref: str | None = None,
        now: datetime | None = None,
    ) -> IncidentTimelineEvent:
        if self.state == "archived":
            raise ValueError("archived_incident_timeline_is_immutable")
        if event_type not in TIMELINE_EVENT_TYPES:
            raise ValueError("unsupported_incident_timeline_event")
        if execution_state not in EXECUTION_STATES:
            raise ValueError("unsupported_incident_execution_state")

        evidence = _refs(evidence_refs)
        if not evidence:
            raise ValueError("incident_timeline_event_requires_evidence")
        sources = _refs(source_record_refs, field="source_record_refs")
        if event_type in CONTAINMENT_EVENT_TYPES and execution_state == "not_applicable":
            raise ValueError("security_action_event_requires_execution_state")
        if execution_state == "uncertain" and not sources:
            raise ValueError("uncertain_execution_requires_source_record")
        if event_type == "reconciliation" and execution_state == "verified":
            if not sources:
                raise ValueError("verified_reconciliation_requires_source_record")
            if not any(ref in self.open_reconciliation_refs for ref in sources):
                raise ValueError("reconciliation_does_not_match_open_uncertainty")

        quarantine_ref = _optional_text(quarantine_object_ref, "quarantine_object_ref")
        recovery = _optional_text(recovery_ref, "recovery_ref")

        event = IncidentTimelineEvent(
            sequence=len(self.timeline) + 1,
            event_type=event_type,
            producer_id=_text(producer_id, "producer_id", 128),
            authority_domain=_text(authority_domain, "authority_domain", 128),
            observed_at=_utc(now),
            summary=_text(summary, "summary", 512),
            evidence_refs=evidence,
            source_record_refs=sources,
            execution_state=execution_state,
            quarantine_object_ref=quarantine_ref,
            recovery_ref=recovery,
        )
        self.timeline.append(event)

        if quarantine_ref and quarantine_ref not in self.quarantine_object_refs:
            self.quarantine_object_refs.append(quarantine_ref)
        if recovery and recovery not in self.recovery_refs:
            self.recovery_refs.append(recovery)
        if execution_state == "uncertain":
            for ref in sources:
                if ref not in self.open_reconciliation_refs:
                    self.open_reconciliation_refs.append(ref)
        if event_type == "reconciliation" and execution_state == "verified":
            matched = set(sources)
            self.open_reconciliation_refs = [
                ref for ref in self.open_reconciliation_refs if ref not in matched
            ]
        if event_type == "everkeep_recovery_evidence":
            for ref in evidence:
                if ref not in self.everkeep_evidence_refs:
                    self.everkeep_evidence_refs.append(ref)
        if event_type == "wardveil_recovery_verification" and execution_state == "verified":
            for ref in evidence:
                if ref not in self.wardveil_recovery_verification_refs:
                    self.wardveil_recovery_verification_refs.append(ref)
        return event

    def transition(
        self,
        new_state: str,
        *,
        actor_id: str,
        reason: str,
        evidence_refs: Iterable[str],
        final_outcome: str | None = None,
        resolution_evidence_refs: Iterable[str] = (),
        now: datetime | None = None,
    ) -> None:
        if new_state not in INCIDENT_STATES:
            raise ValueError("unsupported_incident_state")
        if new_state not in ALLOWED_TRANSITIONS[self.state]:
            raise ValueError(f"incident_transition_not_allowed:{self.state}:{new_state}")

        evidence = _refs(evidence_refs)
        if not evidence:
            raise ValueError("incident_transition_requires_evidence")

        if new_state in {"contained", "verification_pending", "resolved"} and self.reconciliation_open:
            raise ValueError("incident_reconciliation_must_complete_before_state_upgrade")
        if new_state == "contained" and not self._has_verified_containment():
            raise ValueError("contained_incident_requires_verified_containment")
        if new_state == "recovering" and not self.recovery_refs:
            raise ValueError("recovering_requires_recovery_reference")

        resolution_refs: tuple[str, ...] = ()
        final_outcome_text: str | None = None
        if new_state == "resolved":
            resolution_refs = _refs(
                resolution_evidence_refs,
                field="resolution_evidence_refs",
            )
            if not resolution_refs:
                raise ValueError("resolved_incident_requires_resolution_evidence")
            if not final_outcome:
                raise ValueError("resolved_incident_requires_final_outcome")
            if self.recovery_refs:
                if not self.everkeep_evidence_refs:
                    raise ValueError("recovery_linked_incident_requires_everkeep_evidence")
                if not self.wardveil_recovery_verification_refs:
                    raise ValueError("recovery_linked_incident_requires_wardveil_verification")
            final_outcome_text = _text(final_outcome, "final_outcome", 256)

        self._append_transition(
            from_state=self.state,
            to_state=new_state,
            actor_id=actor_id,
            reason=reason,
            evidence_refs=evidence,
            now=now,
        )

        if new_state == "resolved":
            assert final_outcome_text is not None
            self.resolution_evidence_refs = list(resolution_refs)
            self.final_outcome = final_outcome_text
            self.add_timeline_event(
                event_type="resolution",
                producer_id=actor_id,
                authority_domain="security",
                summary=f"Incident resolved: {final_outcome_text}",
                evidence_refs=resolution_refs,
                execution_state="not_applicable",
                now=now,
            )

    def as_record(self) -> dict:
        return {
            "contract_version": CONTRACT_VERSION,
            "record_type": "incident",
            "incident_id": self.incident_id,
            "correlation_id": self.correlation_id,
            "severity": self.severity,
            "state": self.state,
            "owner_role": self.owner_role,
            "target": {
                "authority": self.target_authority,
                "resource_type": self.resource_type,
                "resource_id": self.resource_id,
            },
            "initiating_evidence_refs": list(self.initiating_evidence_refs),
            "source_record_refs": list(self.source_record_refs),
            "quarantine_object_refs": list(self.quarantine_object_refs),
            "recovery_refs": list(self.recovery_refs),
            "everkeep_evidence_refs": list(self.everkeep_evidence_refs),
            "wardveil_recovery_verification_refs": list(
                self.wardveil_recovery_verification_refs
            ),
            "reconciliation_open": self.reconciliation_open,
            "open_reconciliation_refs": list(self.open_reconciliation_refs),
            "timeline": [event.as_record() for event in self.timeline],
            "transitions": [transition.as_record() for transition in self.transitions],
            **(
                {
                    "resolution": {
                        "final_outcome": self.final_outcome,
                        "evidence_refs": list(self.resolution_evidence_refs),
                    }
                }
                if self.final_outcome
                else {}
            ),
        }
