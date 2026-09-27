#!/usr/bin/env python3
"""Wardveil Foundation 0.9 service-identity and signing-key reference.

The reference keeps service identity metadata separate from key material. HMAC
remains reference-only cryptography; production deployments must use approved
key management and authenticated service identity appropriate to the runtime.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Iterable

from reference.wardveil_runtime_authorization import (
    AuthorizationReplayLedger,
    AuthorizationVerification,
    ExecutionAuthorization,
    create_execution_authorization,
    verify_execution_authorization,
)

SERVICE_IDENTITY_VERSION = "0.1.0"
REFERENCE_SIGNATURE_ALGORITHM = "HMAC-SHA256-reference-only"
ISSUER_CAPABILITY = "issue_execution_authorization"
EXECUTOR_CAPABILITY = "execute_protection_action"
SERVICE_STATUSES = {"active", "suspended", "revoked"}
KEY_STATUSES = {"active", "retired", "revoked"}
MAX_ROTATION_OVERLAP = timedelta(hours=24)


def _parse_time(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None
    if parsed.tzinfo is None:
        return None
    try:
        return parsed.astimezone(timezone.utc)
    except OverflowError:
        return None


def _now(value: datetime | None) -> datetime:
    observed = value or datetime.now(timezone.utc)
    if observed.tzinfo is None or observed.utcoffset() is None:
        raise ValueError("timestamp_must_be_timezone_aware")
    try:
        return observed.astimezone(timezone.utc)
    except OverflowError as error:
        raise ValueError("timestamp_out_of_supported_range") from error


@dataclass(frozen=True)
class ServiceIdentity:
    service_id: str
    status: str
    capabilities: frozenset[str]
    created_at: str
    not_before: str
    valid_until: str | None = None

    def as_dict(self) -> dict:
        return {
            "service_identity_version": SERVICE_IDENTITY_VERSION,
            "service_id": self.service_id,
            "status": self.status,
            "capabilities": sorted(self.capabilities),
            "created_at": self.created_at,
            "not_before": self.not_before,
            "valid_until": self.valid_until,
        }


class ServiceIdentityRegistry:
    """Dependency-free registry for first-party Wardveil service identities."""

    def __init__(self, identities: Iterable[ServiceIdentity] = ()) -> None:
        self._identities: dict[str, ServiceIdentity] = {}
        for identity in identities:
            self.register(identity)

    def register(self, identity: ServiceIdentity) -> None:
        if not identity.service_id or identity.status not in SERVICE_STATUSES:
            raise ValueError("invalid_service_identity")
        if not identity.capabilities:
            raise ValueError("service_identity_capability_required")
        created_at = _parse_time(identity.created_at)
        not_before = _parse_time(identity.not_before)
        valid_until = _parse_time(identity.valid_until)
        if created_at is None or not_before is None:
            raise ValueError("invalid_service_identity_time")
        if valid_until is not None and valid_until <= not_before:
            raise ValueError("invalid_service_identity_validity")
        self._identities[identity.service_id] = identity

    def set_status(self, service_id: str, status: str) -> ServiceIdentity:
        if status not in SERVICE_STATUSES:
            raise ValueError("invalid_service_identity_status")
        identity = self._identities.get(service_id)
        if identity is None:
            raise ValueError("unknown_service_identity")
        updated = replace(identity, status=status)
        self._identities[service_id] = updated
        return updated

    def check(self, service_id: str, capability: str, *, now: datetime | None = None) -> str | None:
        identity = self._identities.get(service_id)
        if identity is None:
            return "unknown_service_identity"
        observed = _now(now)
        not_before = _parse_time(identity.not_before)
        valid_until = _parse_time(identity.valid_until)
        assert not_before is not None
        if observed < not_before:
            return "service_identity_not_yet_valid"
        if valid_until is not None and observed >= valid_until:
            return "service_identity_expired"
        if identity.status == "suspended":
            return "service_identity_suspended"
        if identity.status == "revoked":
            return "service_identity_revoked"
        if capability not in identity.capabilities:
            return "service_identity_capability_denied"
        return None

    def metadata(self, service_id: str) -> dict | None:
        identity = self._identities.get(service_id)
        return identity.as_dict() if identity else None


@dataclass(frozen=True)
class SigningKeyMetadata:
    key_id: str
    issuer_id: str
    algorithm: str
    status: str
    created_at: str
    not_before: str
    not_after: str
    retired_at: str | None = None
    revoked_at: str | None = None
    revocation_reason: str | None = None

    def as_dict(self) -> dict:
        return {
            "service_identity_version": SERVICE_IDENTITY_VERSION,
            "key_id": self.key_id,
            "issuer_id": self.issuer_id,
            "algorithm": self.algorithm,
            "status": self.status,
            "created_at": self.created_at,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "retired_at": self.retired_at,
            "revoked_at": self.revoked_at,
            "revocation_reason": self.revocation_reason,
        }


@dataclass(frozen=True)
class KeyResolution:
    accepted: bool
    reason: str
    metadata: SigningKeyMetadata | None = None
    key_material: bytes | None = None


class ReferenceSigningKeyring:
    """Reference key lifecycle with secret material isolated from metadata."""

    def __init__(self, identities: ServiceIdentityRegistry) -> None:
        self.identities = identities
        self._metadata: dict[str, SigningKeyMetadata] = {}
        self._material: dict[str, bytes] = {}

    def add_key(
        self,
        *,
        key_id: str,
        issuer_id: str,
        key_material: bytes,
        not_before: datetime,
        not_after: datetime,
        now: datetime | None = None,
    ) -> SigningKeyMetadata:
        observed = _now(now)
        identity_error = self.identities.check(issuer_id, ISSUER_CAPABILITY, now=observed)
        if identity_error:
            raise ValueError(identity_error)
        if not key_id or key_id in self._metadata:
            raise ValueError("invalid_or_duplicate_signing_key_id")
        if not key_material:
            raise ValueError("signing_key_material_required")
        start = _now(not_before)
        end = _now(not_after)
        if end <= start:
            raise ValueError("invalid_signing_key_validity")
        metadata = SigningKeyMetadata(
            key_id=key_id,
            issuer_id=issuer_id,
            algorithm=REFERENCE_SIGNATURE_ALGORITHM,
            status="active",
            created_at=observed.isoformat(),
            not_before=start.isoformat(),
            not_after=end.isoformat(),
        )
        self._metadata[key_id] = metadata
        self._material[key_id] = bytes(key_material)
        return metadata

    def metadata(self, key_id: str) -> dict | None:
        metadata = self._metadata.get(key_id)
        return metadata.as_dict() if metadata else None

    def all_metadata(self) -> list[dict]:
        return [self._metadata[key].as_dict() for key in sorted(self._metadata)]

    def _resolve(
        self,
        issuer_id: str,
        key_id: str,
        algorithm: str,
        *,
        for_signing: bool,
        now: datetime | None = None,
    ) -> KeyResolution:
        observed = _now(now)
        identity_error = self.identities.check(issuer_id, ISSUER_CAPABILITY, now=observed)
        if identity_error:
            return KeyResolution(False, identity_error)
        metadata = self._metadata.get(key_id)
        if metadata is None:
            return KeyResolution(False, "unknown_signing_key")
        if metadata.issuer_id != issuer_id:
            return KeyResolution(False, "signing_key_issuer_mismatch", metadata)
        if algorithm != metadata.algorithm:
            return KeyResolution(False, "unsupported_signature_algorithm", metadata)
        start = _parse_time(metadata.not_before)
        end = _parse_time(metadata.not_after)
        assert start is not None and end is not None
        if observed < start:
            return KeyResolution(False, "signing_key_not_yet_valid", metadata)
        if observed >= end:
            return KeyResolution(False, "signing_key_expired", metadata)
        if metadata.status == "revoked":
            return KeyResolution(False, "signing_key_revoked", metadata)
        if for_signing and metadata.status == "retired":
            return KeyResolution(False, "signing_key_retired_for_signing", metadata)
        material = self._material.get(key_id)
        if not material:
            return KeyResolution(False, "signing_key_material_unavailable", metadata)
        return KeyResolution(True, "signing_key_available", metadata, material)

    def resolve_for_signing(self, issuer_id: str, key_id: str, *, now: datetime | None = None) -> KeyResolution:
        return self._resolve(
            issuer_id,
            key_id,
            REFERENCE_SIGNATURE_ALGORITHM,
            for_signing=True,
            now=now,
        )

    def resolve_for_verification(
        self,
        issuer_id: str,
        key_id: str,
        algorithm: str,
        *,
        now: datetime | None = None,
    ) -> KeyResolution:
        return self._resolve(issuer_id, key_id, algorithm, for_signing=False, now=now)

    def active_signing_key_id(self, issuer_id: str, *, now: datetime | None = None) -> str:
        candidates: list[SigningKeyMetadata] = []
        for metadata in self._metadata.values():
            if metadata.issuer_id != issuer_id or metadata.status != "active":
                continue
            resolution = self.resolve_for_signing(issuer_id, metadata.key_id, now=now)
            if resolution.accepted:
                candidates.append(metadata)
        if not candidates:
            raise ValueError("no_active_signing_key")
        candidates.sort(key=lambda item: (item.not_before, item.created_at, item.key_id))
        return candidates[-1].key_id

    def rotate(
        self,
        *,
        issuer_id: str,
        current_key_id: str,
        new_key_id: str,
        new_key_material: bytes,
        now: datetime,
        new_not_after: datetime,
        verification_overlap: timedelta = timedelta(minutes=15),
    ) -> tuple[SigningKeyMetadata, SigningKeyMetadata]:
        observed = _now(now)
        if verification_overlap < timedelta(0) or verification_overlap > MAX_ROTATION_OVERLAP:
            raise ValueError("invalid_rotation_overlap")
        current = self._metadata.get(current_key_id)
        if current is None:
            raise ValueError("unknown_signing_key")
        if current.issuer_id != issuer_id:
            raise ValueError("signing_key_issuer_mismatch")
        current_resolution = self.resolve_for_signing(issuer_id, current_key_id, now=observed)
        if not current_resolution.accepted:
            raise ValueError(current_resolution.reason)
        old_end = _parse_time(current.not_after)
        assert old_end is not None
        overlap_end = min(old_end, observed + verification_overlap)
        retired = replace(
            current,
            status="retired",
            retired_at=observed.isoformat(),
            not_after=overlap_end.isoformat(),
        )
        self._metadata[current_key_id] = retired
        created = self.add_key(
            key_id=new_key_id,
            issuer_id=issuer_id,
            key_material=new_key_material,
            not_before=observed,
            not_after=new_not_after,
            now=observed,
        )
        return retired, created

    def revoke(self, key_id: str, *, now: datetime, reason: str) -> SigningKeyMetadata:
        metadata = self._metadata.get(key_id)
        if metadata is None:
            raise ValueError("unknown_signing_key")
        if not reason or len(reason) > 128:
            raise ValueError("revocation_reason_required")
        revoked = replace(
            metadata,
            status="revoked",
            revoked_at=_now(now).isoformat(),
            revocation_reason=reason,
        )
        self._metadata[key_id] = revoked
        return revoked


def create_identity_bound_execution_authorization(
    policy_record: dict,
    *,
    identities: ServiceIdentityRegistry,
    keyring: ReferenceSigningKeyring,
    executor_id: str,
    idempotency_key: str,
    nonce: str,
    key_id: str | None = None,
    now: datetime | None = None,
    ttl: timedelta = timedelta(minutes=2),
) -> ExecutionAuthorization:
    observed = _now(now)
    producer = policy_record.get("producer") or {}
    issuer_id = producer.get("id")
    if not isinstance(issuer_id, str) or not issuer_id:
        raise ValueError("missing_policy_identity")
    issuer_error = identities.check(issuer_id, ISSUER_CAPABILITY, now=observed)
    if issuer_error:
        raise ValueError(issuer_error)
    executor_error = identities.check(executor_id, EXECUTOR_CAPABILITY, now=observed)
    if executor_error:
        raise ValueError(executor_error)
    selected_key = key_id or keyring.active_signing_key_id(issuer_id, now=observed)
    resolution = keyring.resolve_for_signing(issuer_id, selected_key, now=observed)
    if not resolution.accepted or resolution.key_material is None:
        raise ValueError(resolution.reason)
    return create_execution_authorization(
        policy_record,
        signing_key=resolution.key_material,
        signing_key_id=selected_key,
        executor_id=executor_id,
        idempotency_key=idempotency_key,
        nonce=nonce,
        now=observed,
        ttl=ttl,
    )


def verify_identity_bound_execution_authorization(
    authorization: ExecutionAuthorization,
    policy_record: dict,
    *,
    identities: ServiceIdentityRegistry,
    keyring: ReferenceSigningKeyring,
    replay_ledger: AuthorizationReplayLedger,
    now: datetime | None = None,
) -> AuthorizationVerification:
    observed = _now(now)
    issuer_error = identities.check(authorization.issuer_id, ISSUER_CAPABILITY, now=observed)
    if issuer_error:
        return AuthorizationVerification(False, issuer_error)
    executor_error = identities.check(authorization.executor_id, EXECUTOR_CAPABILITY, now=observed)
    if executor_error:
        return AuthorizationVerification(False, executor_error)
    resolution = keyring.resolve_for_verification(
        authorization.issuer_id,
        authorization.signing_key_id,
        authorization.signature_algorithm,
        now=observed,
    )
    if not resolution.accepted or resolution.key_material is None:
        return AuthorizationVerification(False, resolution.reason)
    return verify_execution_authorization(
        authorization,
        policy_record,
        signing_key=resolution.key_material,
        expected_executor_id=authorization.executor_id,
        replay_ledger=replay_ledger,
        now=observed,
    )
