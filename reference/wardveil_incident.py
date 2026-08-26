"""Dependency-free reference layer for Wardveil Quarantine, Audit, and Response.

This module models security control records only. It does not delete files, revoke
credentials, restore backups, or mutate production systems by itself.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from typing import Iterable


REVIEW_STATES = {"pending", "under_review", "released", "removed", "retained"}
INCIDENT_STATES = {"open", "contained", "remediating", "recovering", "verified", "closed"}
SEVERITIES = {"informational", "low", "medium", "high", "critical"}


@dataclass(frozen=True)
class Scope:
    resource_type: str
    resource_id: str
    operation: str | None = None
    principal_class: str | None = None

    def as_dict(self) -> dict:
        data = {"resource_type": self.resource_type, "resource_id": self.resource_id}
        if self.operation:
            data["operation"] = self.operation
        if self.principal_class:
            data["principal_class"] = self.principal_class
        return data


@dataclass(frozen=True)
class Authority:
    actor_id: str
    allowed_actions: frozenset[str]

    def permits(self, action: str) -> bool:
        return action in self.allowed_actions


@dataclass(frozen=True)
class QuarantineRecord:
    record_id: str
    correlation_id: str
    producer_id: str
    scope: Scope
    observed_at: datetime
    review_state: str
    reason: str
    evidence_refs: tuple[str, ...]
    source_record_ids: tuple[str, ...]
    destructive_action: bool = False

    def as_runtime_record(self) -> dict:
        return {
            "contract_version": "0.1.0",
            "record_type": "quarantine_record",
            "record_id": self.record_id,
            "correlation_id": self.correlation_id,
            "producer": {"id": self.producer_id, "authoritative": True},
            "scope": self.scope.as_dict(),
            "observed_at": self.observed_at.isoformat(),
            "evidence_refs": list(self.evidence_refs),
            "review_state": self.review_state,
            "reason": self.reason,
            "source_record_ids": list(self.source_record_ids),
            "destructive_action": self.destructive_action,
        }


@dataclass(frozen=True)
class AuditEvent:
    record_id: str
    correlation_id: str
    producer_id: str
    scope: Scope
    observed_at: datetime
    event_type: str
    outcome: str
    actor_id: str
    evidence_refs: tuple[str, ...]
    previous_event_hash: str | None = None
    event_hash: str | None = None

    def material(self) -> str:
        return "|".join([
            self.record_id,
            self.correlation_id,
            self.producer_id,
            self.scope.resource_type,
            self.scope.resource_id,
            self.observed_at.isoformat(),
            self.event_type,
            self.outcome,
            self.actor_id,
            ",".join(self.evidence_refs),
            self.previous_event_hash or "",
        ])

    def with_hash(self) -> "AuditEvent":
        digest = sha256(self.material().encode("utf-8")).hexdigest()
        return AuditEvent(**{**self.__dict__, "event_hash": digest})

    def as_runtime_record(self) -> dict:
        data = {
            "contract_version": "0.1.0",
            "record_type": "audit_event",
            "record_id": self.record_id,
            "correlation_id": self.correlation_id,
            "producer": {"id": self.producer_id, "authoritative": True},
            "scope": self.scope.as_dict(),
            "observed_at": self.observed_at.isoformat(),
            "evidence_refs": list(self.evidence_refs),
            "event_type": self.event_type,
            "outcome": self.outcome,
            "actor_id": self.actor_id,
        }
        if self.previous_event_hash:
            data["previous_event_hash"] = self.previous_event_hash
        if self.event_hash:
            data["event_hash"] = self.event_hash
        return data


@dataclass(frozen=True)
class IncidentRecord:
    record_id: str
    correlation_id: str
    producer_id: str
    scope: Scope
    observed_at: datetime
    incident_status: str
    severity: str
    evidence_refs: tuple[str, ...]
    source_record_ids: tuple[str, ...]
    response_actions: tuple[str, ...] = field(default_factory=tuple)
    everkeep_recovery_requested: bool = False
    everkeep_recovery_verified: bool = False

    def as_runtime_record(self) -> dict:
        return {
            "contract_version": "0.1.0",
            "record_type": "incident_record",
            "record_id": self.record_id,
            "correlation_id": self.correlation_id,
            "producer": {"id": self.producer_id, "authoritative": True},
            "scope": self.scope.as_dict(),
            "observed_at": self.observed_at.isoformat(),
            "evidence_refs": list(self.evidence_refs),
            "incident_status": self.incident_status,
            "severity": self.severity,
            "source_record_ids": list(self.source_record_ids),
            "response_actions": list(self.response_actions),
            "everkeep_recovery_requested": self.everkeep_recovery_requested,
            "everkeep_recovery_verified": self.everkeep_recovery_verified,
        }


def quarantine(
    *, record_id: str, correlation_id: str, producer_id: str, scope: Scope,
    reason: str, evidence_refs: Iterable[str], source_record_ids: Iterable[str],
    authority: Authority, now: datetime | None = None,
) -> QuarantineRecord:
    if not authority.permits("quarantine"):
        raise PermissionError("executor is not authorized to quarantine this resource")
    refs = tuple(evidence_refs)
    sources = tuple(source_record_ids)
    if not refs or not sources:
        raise ValueError("quarantine requires evidence and source security records")
    return QuarantineRecord(
        record_id, correlation_id, producer_id, scope, now or datetime.now(timezone.utc),
        "pending", reason, refs, sources, False,
    )


def transition_quarantine(record: QuarantineRecord, new_state: str, authority: Authority) -> QuarantineRecord:
    if new_state not in REVIEW_STATES:
        raise ValueError("unsupported quarantine review state")
    required = "release_quarantine" if new_state == "released" else "review_quarantine"
    if new_state == "removed":
        required = "remove_quarantined_content"
    if not authority.permits(required):
        raise PermissionError(f"actor lacks {required} authority")
    if record.review_state in {"released", "removed"}:
        raise ValueError("terminal quarantine state cannot be transitioned")
    return QuarantineRecord(**{**record.__dict__, "review_state": new_state, "destructive_action": new_state == "removed"})


def append_audit_event(
    *, record_id: str, correlation_id: str, producer_id: str, scope: Scope,
    event_type: str, outcome: str, actor_id: str, evidence_refs: Iterable[str],
    previous: AuditEvent | None = None, now: datetime | None = None,
) -> AuditEvent:
    refs = tuple(evidence_refs)
    if not refs:
        raise ValueError("audit event requires evidence references")
    event = AuditEvent(
        record_id, correlation_id, producer_id, scope, now or datetime.now(timezone.utc),
        event_type, outcome, actor_id, refs, previous.event_hash if previous else None,
    )
    return event.with_hash()


def verify_audit_chain(events: Iterable[AuditEvent]) -> bool:
    prior_hash = None
    for event in events:
        if event.previous_event_hash != prior_hash:
            return False
        expected = sha256(event.material().encode("utf-8")).hexdigest()
        if event.event_hash != expected:
            return False
        prior_hash = event.event_hash
    return True


def create_incident(
    *, record_id: str, correlation_id: str, producer_id: str, scope: Scope,
    severity: str, evidence_refs: Iterable[str], source_record_ids: Iterable[str],
    now: datetime | None = None,
) -> IncidentRecord:
    if severity not in SEVERITIES:
        raise ValueError("unsupported incident severity")
    refs = tuple(evidence_refs)
    sources = tuple(source_record_ids)
    if not refs or not sources:
        raise ValueError("incident creation requires evidence and source records")
    return IncidentRecord(
        record_id, correlation_id, producer_id, scope, now or datetime.now(timezone.utc),
        "open", severity, refs, sources,
    )


def transition_incident(
    incident: IncidentRecord, new_status: str, *, authority: Authority,
    response_action: str | None = None, everkeep_recovery_requested: bool | None = None,
    everkeep_recovery_verified: bool | None = None,
) -> IncidentRecord:
    order = ["open", "contained", "remediating", "recovering", "verified", "closed"]
    if new_status not in INCIDENT_STATES:
        raise ValueError("unsupported incident status")
    current_index = order.index(incident.incident_status)
    next_index = order.index(new_status)
    if next_index < current_index or next_index > current_index + 1:
        raise ValueError("incident transitions must move forward one state at a time")
    required_action = {
        "contained": "contain_incident",
        "remediating": "remediate_incident",
        "recovering": "coordinate_recovery",
        "verified": "verify_recovery",
        "closed": "close_incident",
    }.get(new_status)
    if required_action and not authority.permits(required_action):
        raise PermissionError(f"actor lacks {required_action} authority")

    recovery_requested = incident.everkeep_recovery_requested if everkeep_recovery_requested is None else everkeep_recovery_requested
    recovery_verified = incident.everkeep_recovery_verified if everkeep_recovery_verified is None else everkeep_recovery_verified
    if new_status == "recovering" and not recovery_requested:
        raise ValueError("recovering requires an explicit Everkeep recovery request or equivalent recovery authority evidence")
    if new_status in {"verified", "closed"} and recovery_requested and not recovery_verified:
        raise ValueError("recovery-dependent incident cannot be verified or closed before recovery verification")

    actions = incident.response_actions + ((response_action,) if response_action else ())
    return IncidentRecord(**{
        **incident.__dict__,
        "incident_status": new_status,
        "response_actions": actions,
        "everkeep_recovery_requested": recovery_requested,
        "everkeep_recovery_verified": recovery_verified,
    })
