"""Dependency-free Wardveil event transport reference for GoreeCloud Mesh.

This module validates and signs transport envelopes for conformance testing only.
It does not provide a production message bus, key-management system, or durable store.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import hmac
import json
from typing import Iterable
from uuid import uuid4

ALLOWED_RECORD_TYPES = {
    "trust_decision", "policy_decision", "detection_finding", "scan_finding",
    "protection_action", "quarantine_record", "incident_record", "audit_event",
}
RETENTION_CLASSES = {"transient", "security_event", "incident_evidence", "audit_evidence"}


def _canonical(data: object) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class ConsumerPolicy:
    consumer_id: str
    allowed_record_types: frozenset[str]
    allowed_resource_types: frozenset[str] = field(default_factory=frozenset)

    def authorizes(self, record_type: str, resource_type: str) -> bool:
        if record_type not in self.allowed_record_types:
            return False
        return not self.allowed_resource_types or resource_type in self.allowed_resource_types


@dataclass(frozen=True)
class MeshEnvelope:
    envelope_id: str
    replay_key: str
    retention_class: str
    audience: tuple[str, ...]
    created_at: str
    expires_at: str
    payload_digest: str
    signature_algorithm: str
    signature: str
    record: dict

    def as_dict(self) -> dict:
        return {
            "envelope_version": "0.1.0",
            "envelope_id": self.envelope_id,
            "replay_key": self.replay_key,
            "retention_class": self.retention_class,
            "audience": list(self.audience),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "payload_digest": self.payload_digest,
            "signature_algorithm": self.signature_algorithm,
            "signature": self.signature,
            "record": self.record,
        }


class ReplayLedger:
    def __init__(self) -> None:
        self._accepted: dict[str, str] = {}

    def remember(self, replay_key: str, envelope_id: str) -> bool:
        existing = self._accepted.get(replay_key)
        if existing is None:
            self._accepted[replay_key] = envelope_id
            return True
        return existing == envelope_id


def create_envelope(
    record: dict,
    *,
    signing_key: bytes,
    audience: Iterable[str],
    replay_key: str,
    retention_class: str = "security_event",
    now: datetime | None = None,
) -> MeshEnvelope:
    observed = now or datetime.now(timezone.utc)
    _validate_record(record, observed)
    if not signing_key:
        raise ValueError("signing key is required")
    recipients = tuple(dict.fromkeys(x for x in audience if isinstance(x, str) and x.strip()))
    if not recipients:
        raise ValueError("at least one authorized audience is required")
    if not replay_key or not replay_key.strip():
        raise ValueError("replay key is required")
    if retention_class not in RETENTION_CLASSES:
        raise ValueError("unsupported retention class")

    valid_until = _parse_time(record.get("valid_until")) or observed
    expires = min(valid_until, observed.replace(microsecond=0) if valid_until <= observed else valid_until)
    if expires <= observed:
        raise ValueError("cannot transport expired security evidence")

    digest = sha256(_canonical(record)).hexdigest()
    material = {
        "envelope_version": "0.1.0",
        "replay_key": replay_key.strip(),
        "retention_class": retention_class,
        "audience": list(recipients),
        "created_at": observed.isoformat(),
        "expires_at": expires.isoformat(),
        "payload_digest": digest,
        "record_id": record["record_id"],
        "correlation_id": record["correlation_id"],
    }
    signature = hmac.new(signing_key, _canonical(material), sha256).hexdigest()
    return MeshEnvelope(
        envelope_id=f"mesh-{uuid4()}",
        replay_key=replay_key.strip(),
        retention_class=retention_class,
        audience=recipients,
        created_at=observed.isoformat(),
        expires_at=expires.isoformat(),
        payload_digest=digest,
        signature_algorithm="HMAC-SHA256-reference-only",
        signature=signature,
        record=dict(record),
    )


def verify_and_accept(
    envelope: MeshEnvelope,
    *,
    signing_key: bytes,
    consumer: ConsumerPolicy,
    replay_ledger: ReplayLedger,
    now: datetime | None = None,
) -> dict:
    observed = now or datetime.now(timezone.utc)
    if consumer.consumer_id not in envelope.audience:
        return {"accepted": False, "reason": "consumer_not_in_audience"}
    if envelope.retention_class not in RETENTION_CLASSES:
        return {"accepted": False, "reason": "unsupported_retention_class"}
    if envelope.signature_algorithm != "HMAC-SHA256-reference-only":
        return {"accepted": False, "reason": "unsupported_signature_algorithm"}
    if sha256(_canonical(envelope.record)).hexdigest() != envelope.payload_digest:
        return {"accepted": False, "reason": "payload_digest_mismatch"}
    expires_at = _parse_time(envelope.expires_at)
    if expires_at is None or expires_at <= observed:
        return {"accepted": False, "reason": "expired_envelope"}

    record = envelope.record
    try:
        _validate_record(record, observed)
    except ValueError as exc:
        return {"accepted": False, "reason": str(exc)}

    scope = record.get("scope") or {}
    resource_type = scope.get("resource_type")
    if not consumer.authorizes(record["record_type"], resource_type):
        return {"accepted": False, "reason": "consumer_not_authorized_for_scope"}

    material = {
        "envelope_version": "0.1.0",
        "replay_key": envelope.replay_key,
        "retention_class": envelope.retention_class,
        "audience": list(envelope.audience),
        "created_at": envelope.created_at,
        "expires_at": envelope.expires_at,
        "payload_digest": envelope.payload_digest,
        "record_id": record["record_id"],
        "correlation_id": record["correlation_id"],
    }
    expected = hmac.new(signing_key, _canonical(material), sha256).hexdigest()
    if not hmac.compare_digest(expected, envelope.signature):
        return {"accepted": False, "reason": "invalid_signature"}

    if not replay_ledger.remember(envelope.replay_key, envelope.envelope_id):
        return {"accepted": False, "reason": "replay_key_conflict"}

    return {
        "accepted": True,
        "reason": "validated_authorized_delivery",
        "record": record,
        "delivery_authority_transferred": False,
    }


def _validate_record(record: dict, now: datetime) -> None:
    if not isinstance(record, dict):
        raise ValueError("invalid_record")
    if record.get("record_type") not in ALLOWED_RECORD_TYPES:
        raise ValueError("unsupported_record_type")
    if not record.get("record_id") or not record.get("correlation_id"):
        raise ValueError("missing_record_identity")
    producer = record.get("producer") or {}
    if producer.get("authoritative") is not True or not producer.get("id"):
        raise ValueError("non_authoritative_record")
    scope = record.get("scope") or {}
    if not scope.get("resource_type") or not scope.get("resource_id"):
        raise ValueError("invalid_record_scope")
    valid_until = _parse_time(record.get("valid_until"))
    if valid_until is not None and valid_until <= now:
        raise ValueError("expired_security_evidence")
    if record.get("record_type") in {"trust_decision", "policy_decision", "detection_finding", "scan_finding", "protection_action"} and valid_until is None:
        raise ValueError("missing_security_evidence_validity")
