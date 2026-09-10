#!/usr/bin/env python3
"""Wardveil next-upgrade Audit and Evidence Ledger reference model.

This source-level model records privacy-minimized security provenance. It does
not execute protection actions, authorize access, mutate targets, provide
production durable storage, or establish a Wardveil protection claim.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from typing import Iterable
from uuid import uuid4

CONTRACT_VERSION = "0.1.0"
RETENTION_CLASS = "audit_evidence"
RETENTION_DAYS = 365

EVENT_CATEGORIES = (
    "security_decision",
    "execution",
    "reconciliation",
    "recovery_verification",
    "security_observation",
)
OUTCOMES = (
    "requested",
    "succeeded",
    "failed",
    "denied",
    "blocked",
    "partial",
    "unknown",
    "reconciled",
)
RECONCILIATION_STATES = ("not_applicable", "not_required", "required", "reconciled")
RECONCILED_OUTCOMES = ("succeeded", "failed", "not_executed", "unknown")

SENSITIVE_MARKERS = (
    "authorization: bearer ",
    "bearer ",
    "begin private key",
    "begin rsa private key",
    "password=",
    "passwd=",
    "secret=",
    "token=",
    "api_key=",
    "apikey=",
)


def _utc(value: datetime | None = None) -> datetime:
    value = value or datetime.now(timezone.utc)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp_must_be_timezone_aware")
    return value.astimezone(timezone.utc)


def _text(
    value: str,
    field: str,
    max_length: int = 256,
    *,
    privacy_check: bool = True,
) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise ValueError(f"{field}_required")
    if len(normalized) > max_length:
        raise ValueError(f"{field}_too_long")
    if privacy_check:
        lowered = normalized.lower()
        if any(marker in lowered for marker in SENSITIVE_MARKERS):
            raise ValueError(f"{field}_contains_prohibited_sensitive_material")
    return normalized


def _optional_text(
    value: str | None,
    field: str,
    max_length: int = 256,
    *,
    privacy_check: bool = True,
) -> str | None:
    if value is None:
        return None
    return _text(value, field, max_length, privacy_check=privacy_check)


def _refs(values: Iterable[str], *, field: str, max_items: int = 64) -> tuple[str, ...]:
    normalized = tuple(
        dict.fromkeys(str(value).strip() for value in values if str(value).strip())
    )
    if len(normalized) > max_items:
        raise ValueError(f"{field}_too_many")
    for value in normalized:
        _text(value, field, 256)
    return normalized


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class AuditEvent:
    sequence: int
    audit_event_id: str
    correlation_id: str
    event_category: str
    producer_id: str
    authority_domain: str
    observed_at: datetime
    evidence_observed_at: datetime
    evidence_valid_until: datetime | None
    actor_id: str | None
    service_identity_id: str | None
    policy_id: str | None
    authorization_id: str | None
    executor_id: str | None
    signing_key_id: str | None
    target_authority: str
    resource_type: str
    resource_id: str
    requested_action: str
    outcome: str
    evidence_refs: tuple[str, ...]
    verification_evidence_refs: tuple[str, ...]
    source_record_refs: tuple[str, ...]
    reconciliation_state: str
    reconciles_audit_event_id: str | None
    reconciled_outcome: str | None
    incident_ref: str | None
    quarantine_object_ref: str | None
    reason_code: str
    summary: str
    retention_class: str
    expires_at: datetime
    previous_event_hash: str | None
    event_hash: str

    def freshness(self, *, as_of: datetime | None = None) -> str:
        if self.evidence_valid_until is None:
            return "historical_no_current_validity"
        as_of = _utc(as_of)
        return "current" if as_of < self.evidence_valid_until else "expired"

    def material_record(self) -> dict:
        return {
            "contract_version": CONTRACT_VERSION,
            "record_type": "audit_event",
            "sequence": self.sequence,
            "audit_event_id": self.audit_event_id,
            "correlation_id": self.correlation_id,
            "event_category": self.event_category,
            "producer": {
                "id": self.producer_id,
                "authority_domain": self.authority_domain,
            },
            "observed_at": self.observed_at.isoformat(),
            "evidence_observed_at": self.evidence_observed_at.isoformat(),
            **(
                {"evidence_valid_until": self.evidence_valid_until.isoformat()}
                if self.evidence_valid_until
                else {}
            ),
            **({"actor_id": self.actor_id} if self.actor_id else {}),
            **({"service_identity_id": self.service_identity_id} if self.service_identity_id else {}),
            **({"policy_id": self.policy_id} if self.policy_id else {}),
            **({"authorization_id": self.authorization_id} if self.authorization_id else {}),
            **({"executor_id": self.executor_id} if self.executor_id else {}),
            **({"signing_key_id": self.signing_key_id} if self.signing_key_id else {}),
            "target": {
                "authority": self.target_authority,
                "resource_type": self.resource_type,
                "resource_id": self.resource_id,
            },
            "requested_action": self.requested_action,
            "outcome": self.outcome,
            "evidence_refs": list(self.evidence_refs),
            "verification_evidence_refs": list(self.verification_evidence_refs),
            "source_record_refs": list(self.source_record_refs),
            "reconciliation_state": self.reconciliation_state,
            **(
                {"reconciles_audit_event_id": self.reconciles_audit_event_id}
                if self.reconciles_audit_event_id
                else {}
            ),
            **(
                {"reconciled_outcome": self.reconciled_outcome}
                if self.reconciled_outcome
                else {}
            ),
            **({"incident_ref": self.incident_ref} if self.incident_ref else {}),
            **(
                {"quarantine_object_ref": self.quarantine_object_ref}
                if self.quarantine_object_ref
                else {}
            ),
            "reason_code": self.reason_code,
            "summary": self.summary,
            "retention": {
                "class": self.retention_class,
                "purpose": "security_provenance",
                "expires_at": self.expires_at.isoformat(),
                "access_authority": "wardveil-audit",
                "may_leave_origin": False,
            },
            **(
                {"previous_event_hash": self.previous_event_hash}
                if self.previous_event_hash
                else {}
            ),
        }

    def as_record(self) -> dict:
        return {**self.material_record(), "event_hash": self.event_hash}


class AuditLedger:
    """Append-only in-memory conformance ledger with hash-linked provenance."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []
        self._ids: set[str] = set()
        self._open_reconciliation: set[str] = set()

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)

    @property
    def open_reconciliation_event_ids(self) -> tuple[str, ...]:
        return tuple(
            event.audit_event_id
            for event in self._events
            if event.audit_event_id in self._open_reconciliation
        )

    def append(
        self,
        *,
        correlation_id: str,
        event_category: str,
        producer_id: str,
        authority_domain: str,
        target_authority: str,
        resource_type: str,
        resource_id: str,
        requested_action: str,
        outcome: str,
        evidence_refs: Iterable[str],
        source_record_refs: Iterable[str],
        reason_code: str,
        summary: str,
        actor_id: str | None = None,
        service_identity_id: str | None = None,
        policy_id: str | None = None,
        authorization_id: str | None = None,
        executor_id: str | None = None,
        signing_key_id: str | None = None,
        verification_evidence_refs: Iterable[str] = (),
        reconciliation_state: str = "not_applicable",
        reconciles_audit_event_id: str | None = None,
        reconciled_outcome: str | None = None,
        incident_ref: str | None = None,
        quarantine_object_ref: str | None = None,
        evidence_observed_at: datetime | None = None,
        evidence_valid_until: datetime | None = None,
        audit_event_id: str | None = None,
        now: datetime | None = None,
    ) -> AuditEvent:
        if event_category not in EVENT_CATEGORIES:
            raise ValueError("unsupported_audit_event_category")
        if outcome not in OUTCOMES:
            raise ValueError("unsupported_audit_outcome")
        if reconciliation_state not in RECONCILIATION_STATES:
            raise ValueError("unsupported_reconciliation_state")

        observed_at = _utc(now)
        evidence_at = _utc(evidence_observed_at or observed_at)
        valid_until = _utc(evidence_valid_until) if evidence_valid_until else None
        if evidence_at > observed_at:
            raise ValueError("future_dated_evidence_not_allowed")
        if valid_until is not None and valid_until <= evidence_at:
            raise ValueError("evidence_validity_must_follow_observation")

        event_id = _text(
            audit_event_id or f"audit-{uuid4()}",
            "audit_event_id",
            160,
        )
        if event_id in self._ids:
            raise ValueError("duplicate_audit_event_id")

        refs = _refs(evidence_refs, field="evidence_refs")
        sources = _refs(source_record_refs, field="source_record_refs")
        verification = _refs(
            verification_evidence_refs,
            field="verification_evidence_refs",
        )
        if not refs:
            raise ValueError("audit_event_requires_evidence")
        if not sources:
            raise ValueError("audit_event_requires_source_records")

        actor = _optional_text(actor_id, "actor_id", 128)
        service_identity = _optional_text(service_identity_id, "service_identity_id", 128)
        if not actor and not service_identity:
            raise ValueError("audit_event_requires_acting_identity")

        policy = _optional_text(policy_id, "policy_id", 160)
        authorization = _optional_text(authorization_id, "authorization_id", 160)
        executor = _optional_text(executor_id, "executor_id", 128)
        signing_key = _optional_text(signing_key_id, "signing_key_id", 160)
        reconciles = _optional_text(
            reconciles_audit_event_id,
            "reconciles_audit_event_id",
            160,
        )
        incident = _optional_text(incident_ref, "incident_ref", 256)
        quarantine = _optional_text(quarantine_object_ref, "quarantine_object_ref", 256)

        if event_category == "execution":
            if not authorization or not executor:
                raise ValueError("execution_audit_requires_authorization_and_executor")
            if outcome == "succeeded" and not verification:
                raise ValueError("successful_execution_requires_verification_evidence")
            if outcome == "unknown" and reconciliation_state != "required":
                raise ValueError("uncertain_execution_requires_reconciliation")
            if outcome != "unknown" and reconciliation_state == "required":
                raise ValueError("reconciliation_required_only_for_uncertain_execution")

        if event_category == "reconciliation":
            if not reconciles:
                raise ValueError("reconciliation_requires_original_audit_event")
            if reconciles not in self._open_reconciliation:
                raise ValueError("reconciliation_does_not_match_open_uncertainty")
            if reconciled_outcome not in RECONCILED_OUTCOMES:
                raise ValueError("reconciliation_requires_bounded_outcome")
            if reconciliation_state not in {"required", "reconciled"}:
                raise ValueError("reconciliation_state_invalid_for_reconciliation_event")
            if reconciled_outcome == "unknown":
                if reconciliation_state != "required":
                    raise ValueError("unknown_reconciliation_must_remain_required")
            elif reconciliation_state != "reconciled":
                raise ValueError("verified_reconciliation_must_close_reconciliation")

        if event_category != "reconciliation" and (
            reconciles is not None or reconciled_outcome is not None
        ):
            raise ValueError("reconciliation_fields_only_allowed_on_reconciliation_events")

        previous_hash = self._events[-1].event_hash if self._events else None
        expires_at = observed_at + timedelta(days=RETENTION_DAYS)

        event = AuditEvent(
            sequence=len(self._events) + 1,
            audit_event_id=event_id,
            correlation_id=_text(correlation_id, "correlation_id", 160),
            event_category=event_category,
            producer_id=_text(producer_id, "producer_id", 128),
            authority_domain=_text(authority_domain, "authority_domain", 128),
            observed_at=observed_at,
            evidence_observed_at=evidence_at,
            evidence_valid_until=valid_until,
            actor_id=actor,
            service_identity_id=service_identity,
            policy_id=policy,
            authorization_id=authorization,
            executor_id=executor,
            signing_key_id=signing_key,
            target_authority=_text(target_authority, "target_authority", 128),
            resource_type=_text(resource_type, "resource_type", 128),
            resource_id=_text(resource_id, "resource_id", 256),
            requested_action=_text(requested_action, "requested_action", 128),
            outcome=outcome,
            evidence_refs=refs,
            verification_evidence_refs=verification,
            source_record_refs=sources,
            reconciliation_state=reconciliation_state,
            reconciles_audit_event_id=reconciles,
            reconciled_outcome=reconciled_outcome,
            incident_ref=incident,
            quarantine_object_ref=quarantine,
            reason_code=_text(reason_code, "reason_code", 128),
            summary=_text(summary, "summary", 512),
            retention_class=RETENTION_CLASS,
            expires_at=expires_at,
            previous_event_hash=previous_hash,
            event_hash="",
        )
        digest = sha256(_canonical(event.material_record())).hexdigest()
        event = AuditEvent(**{**event.__dict__, "event_hash": digest})

        self._events.append(event)
        self._ids.add(event.audit_event_id)

        if event.event_category == "execution" and event.outcome == "unknown":
            self._open_reconciliation.add(event.audit_event_id)
        if event.event_category == "reconciliation":
            assert event.reconciles_audit_event_id is not None
            if event.reconciled_outcome != "unknown":
                self._open_reconciliation.remove(event.reconciles_audit_event_id)

        return event

    def verify_chain(self) -> bool:
        previous_hash: str | None = None
        for expected_sequence, event in enumerate(self._events, start=1):
            if event.sequence != expected_sequence:
                return False
            if event.previous_event_hash != previous_hash:
                return False
            if sha256(_canonical(event.material_record())).hexdigest() != event.event_hash:
                return False
            previous_hash = event.event_hash
        return True

    def explain(self, audit_event_id: str, *, as_of: datetime | None = None) -> dict:
        event = next(
            (candidate for candidate in self._events if candidate.audit_event_id == audit_event_id),
            None,
        )
        if event is None:
            raise ValueError("audit_event_not_found")
        return {
            "audit_event_id": event.audit_event_id,
            "correlation_id": event.correlation_id,
            "producer_id": event.producer_id,
            "authority_domain": event.authority_domain,
            "acting_identity": event.actor_id or event.service_identity_id,
            "target": {
                "authority": event.target_authority,
                "resource_type": event.resource_type,
                "resource_id": event.resource_id,
            },
            "requested_action": event.requested_action,
            "outcome": event.outcome,
            "evidence_freshness": event.freshness(as_of=as_of),
            "reconciliation_state": event.reconciliation_state,
            "evidence_refs": list(event.evidence_refs),
            "verification_evidence_refs": list(event.verification_evidence_refs),
            "incident_ref": event.incident_ref,
            "quarantine_object_ref": event.quarantine_object_ref,
            "reason_code": event.reason_code,
            "summary": event.summary,
        }
