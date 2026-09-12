#!/usr/bin/env python3
"""Dependency-free Wardveil runtime execution-authorization reference.

This module defines the cross-service authorization boundary between an
existing authoritative Wardveil Policy decision and a concrete Wardveil
Protect executor. It uses HMAC-SHA256 only as a reference/conformance
mechanism; production deployments must use approved key management and
authenticated transport appropriate to their environment.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import hmac
import json
from typing import Callable
from uuid import uuid4

from reference.wardveil_protect import ExecutorAuthority, ProtectEngine, ProtectionResult

AUTHORIZATION_VERSION = "0.1.0"
SIGNATURE_ALGORITHM = "HMAC-SHA256-reference-only"
DEFAULT_REFERENCE_SIGNING_KEY_ID = "reference-static"
MAX_AUTHORIZATION_TTL = timedelta(minutes=5)
MAX_SIGNING_KEY_ID_LENGTH = 128
MAX_AUTHORIZATION_IDENTITY_LENGTH = 256
POLICY_ACTIONS = {
    "allow", "allow_and_log", "warn", "step_up", "restrict",
    "quarantine", "revoke", "block", "isolate", "escalate",
}
HIGH_IMPACT_ACTIONS = {"restrict", "quarantine", "revoke", "block", "isolate", "escalate"}


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _canonical_identifier(value: object, maximum: int) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip()
        and len(value) <= maximum
        and not any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value)
    )


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


def _policy_error(policy_record: object, now: datetime) -> str | None:
    if not isinstance(policy_record, dict):
        return "invalid_policy_record"
    if policy_record.get("record_type") != "policy_decision":
        return "invalid_policy_record_type"
    if policy_record.get("contract_version") != "0.1.0":
        return "unsupported_policy_contract"
    if not policy_record.get("record_id") or not policy_record.get("correlation_id"):
        return "missing_policy_identity"
    producer = policy_record.get("producer") or {}
    if producer.get("authoritative") is not True or not producer.get("id"):
        return "non_authoritative_policy_record"
    scope = policy_record.get("scope") or {}
    if not scope.get("resource_type") or not scope.get("resource_id"):
        return "invalid_policy_scope"
    if policy_record.get("policy_decision") not in POLICY_ACTIONS:
        return "unsupported_policy_action"
    valid_until = _parse_time(policy_record.get("valid_until"))
    if valid_until is None or valid_until <= now:
        return "expired_or_missing_policy_validity"
    return None


@dataclass(frozen=True)
class ExecutionAuthorization:
    authorization_id: str
    issuer_id: str
    policy_record_id: str
    correlation_id: str
    executor_id: str
    action: str
    scope: dict
    idempotency_key: str
    nonce: str
    issued_at: str
    expires_at: str
    policy_digest_sha256: str
    signing_key_id: str
    signature_algorithm: str
    signature: str

    def signing_material(self) -> dict:
        return {
            "authorization_version": AUTHORIZATION_VERSION,
            "authorization_id": self.authorization_id,
            "issuer_id": self.issuer_id,
            "policy_record_id": self.policy_record_id,
            "correlation_id": self.correlation_id,
            "executor_id": self.executor_id,
            "action": self.action,
            "scope": dict(self.scope),
            "idempotency_key": self.idempotency_key,
            "nonce": self.nonce,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "policy_digest_sha256": self.policy_digest_sha256,
            "signing_key_id": self.signing_key_id,
        }

    def as_dict(self) -> dict:
        return {
            **self.signing_material(),
            "signature_algorithm": self.signature_algorithm,
            "signature": self.signature,
        }


class AuthorizationReplayLedger:
    """Reference replay ledger with idempotent retry semantics.

    Reusing the exact same authorization ID, nonce, and idempotency key is an
    idempotent retry. Reusing a nonce for different authorization material is a
    conflict and is rejected. Production deployments require a durable/shared
    ledger for the executor scope they protect.
    """

    def __init__(self) -> None:
        self._accepted: dict[str, tuple[str, str]] = {}

    def accept(self, nonce: str, authorization_id: str, idempotency_key: str) -> str:
        candidate = (authorization_id, idempotency_key)
        existing = self._accepted.get(nonce)
        if existing is None:
            self._accepted[nonce] = candidate
            return "new"
        if existing == candidate:
            return "idempotent"
        return "conflict"


@dataclass(frozen=True)
class AuthorizationVerification:
    accepted: bool
    reason: str
    idempotent_replay: bool = False


@dataclass(frozen=True)
class AuthorizedExecutionResult:
    authorization: AuthorizationVerification
    protection_result: ProtectionResult | None


def create_execution_authorization(
    policy_record: dict,
    *,
    signing_key: bytes,
    signing_key_id: str = DEFAULT_REFERENCE_SIGNING_KEY_ID,
    executor_id: str,
    idempotency_key: str,
    nonce: str,
    now: datetime | None = None,
    ttl: timedelta = timedelta(minutes=2),
) -> ExecutionAuthorization:
    observed = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    error = _policy_error(policy_record, observed)
    if error:
        raise ValueError(error)
    if not signing_key:
        raise ValueError("signing_key_required")
    if not _canonical_identifier(signing_key_id, MAX_SIGNING_KEY_ID_LENGTH):
        raise ValueError("signing_key_id_required")
    if not _canonical_identifier(executor_id, MAX_AUTHORIZATION_IDENTITY_LENGTH):
        raise ValueError("executor_id_required")
    if not _canonical_identifier(idempotency_key, MAX_AUTHORIZATION_IDENTITY_LENGTH):
        raise ValueError("idempotency_key_required")
    if not _canonical_identifier(nonce, MAX_AUTHORIZATION_IDENTITY_LENGTH):
        raise ValueError("nonce_required")
    if ttl <= timedelta(0) or ttl > MAX_AUTHORIZATION_TTL:
        raise ValueError("invalid_authorization_ttl")

    policy_valid_until = _parse_time(policy_record["valid_until"])
    assert policy_valid_until is not None
    expires = min(observed + ttl, policy_valid_until)
    if expires <= observed:
        raise ValueError("authorization_would_be_expired")

    scope = dict(policy_record["scope"])
    authorization_id = f"authz-{uuid4()}"
    policy_digest = sha256(_canonical(policy_record)).hexdigest()
    material = {
        "authorization_version": AUTHORIZATION_VERSION,
        "authorization_id": authorization_id,
        "issuer_id": policy_record["producer"]["id"],
        "policy_record_id": policy_record["record_id"],
        "correlation_id": policy_record["correlation_id"],
        "executor_id": executor_id,
        "action": policy_record["policy_decision"],
        "scope": scope,
        "idempotency_key": idempotency_key,
        "nonce": nonce,
        "issued_at": observed.isoformat(),
        "expires_at": expires.isoformat(),
        "policy_digest_sha256": policy_digest,
        "signing_key_id": signing_key_id,
    }
    signature = hmac.new(signing_key, _canonical(material), sha256).hexdigest()
    return ExecutionAuthorization(
        authorization_id=authorization_id,
        issuer_id=material["issuer_id"],
        policy_record_id=material["policy_record_id"],
        correlation_id=material["correlation_id"],
        executor_id=material["executor_id"],
        action=material["action"],
        scope=scope,
        idempotency_key=material["idempotency_key"],
        nonce=material["nonce"],
        issued_at=material["issued_at"],
        expires_at=material["expires_at"],
        policy_digest_sha256=policy_digest,
        signing_key_id=material["signing_key_id"],
        signature_algorithm=SIGNATURE_ALGORITHM,
        signature=signature,
    )


def verify_execution_authorization(
    authorization: ExecutionAuthorization,
    policy_record: dict,
    *,
    signing_key: bytes,
    expected_executor_id: str,
    replay_ledger: AuthorizationReplayLedger,
    now: datetime | None = None,
    clock_skew: timedelta = timedelta(seconds=30),
) -> AuthorizationVerification:
    observed = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if not signing_key:
        return AuthorizationVerification(False, "signing_key_required")
    if authorization.signature_algorithm != SIGNATURE_ALGORITHM:
        return AuthorizationVerification(False, "unsupported_signature_algorithm")
    if not _canonical_identifier(authorization.signing_key_id, MAX_SIGNING_KEY_ID_LENGTH):
        return AuthorizationVerification(False, "signing_key_id_required")
    if (
        not _canonical_identifier(expected_executor_id, MAX_AUTHORIZATION_IDENTITY_LENGTH)
        or not _canonical_identifier(authorization.executor_id, MAX_AUTHORIZATION_IDENTITY_LENGTH)
        or authorization.executor_id != expected_executor_id
    ):
        return AuthorizationVerification(False, "executor_binding_mismatch")
    if (
        not _canonical_identifier(authorization.idempotency_key, MAX_AUTHORIZATION_IDENTITY_LENGTH)
        or not _canonical_identifier(authorization.nonce, MAX_AUTHORIZATION_IDENTITY_LENGTH)
    ):
        return AuthorizationVerification(False, "missing_replay_identity")

    policy_error = _policy_error(policy_record, observed)
    if policy_error:
        return AuthorizationVerification(False, policy_error)

    issued_at = _parse_time(authorization.issued_at)
    expires_at = _parse_time(authorization.expires_at)
    if issued_at is None or expires_at is None:
        return AuthorizationVerification(False, "invalid_authorization_time")
    if issued_at > observed + clock_skew:
        return AuthorizationVerification(False, "future_dated_authorization")
    if expires_at <= observed:
        return AuthorizationVerification(False, "expired_authorization")
    if expires_at <= issued_at or expires_at - issued_at > MAX_AUTHORIZATION_TTL:
        return AuthorizationVerification(False, "invalid_authorization_validity_window")

    policy_valid_until = _parse_time(policy_record.get("valid_until"))
    assert policy_valid_until is not None
    if expires_at > policy_valid_until:
        return AuthorizationVerification(False, "authorization_outlives_policy")

    expected_digest = sha256(_canonical(policy_record)).hexdigest()
    if authorization.policy_digest_sha256 != expected_digest:
        return AuthorizationVerification(False, "policy_digest_mismatch")
    if authorization.policy_record_id != policy_record.get("record_id"):
        return AuthorizationVerification(False, "policy_record_binding_mismatch")
    if authorization.correlation_id != policy_record.get("correlation_id"):
        return AuthorizationVerification(False, "correlation_binding_mismatch")
    if authorization.issuer_id != (policy_record.get("producer") or {}).get("id"):
        return AuthorizationVerification(False, "issuer_binding_mismatch")
    if authorization.action != policy_record.get("policy_decision"):
        return AuthorizationVerification(False, "action_binding_mismatch")
    if authorization.scope != policy_record.get("scope"):
        return AuthorizationVerification(False, "scope_binding_mismatch")

    expected_signature = hmac.new(signing_key, _canonical(authorization.signing_material()), sha256).hexdigest()
    if not hmac.compare_digest(expected_signature, authorization.signature):
        return AuthorizationVerification(False, "invalid_authorization_signature")

    replay_state = replay_ledger.accept(
        authorization.nonce,
        authorization.authorization_id,
        authorization.idempotency_key,
    )
    if replay_state == "conflict":
        return AuthorizationVerification(False, "authorization_nonce_conflict")
    return AuthorizationVerification(
        True,
        "idempotent_authorization_replay" if replay_state == "idempotent" else "validated_execution_authorization",
        replay_state == "idempotent",
    )


class AuthorizedProtectEngine:
    """Canonical 0.9 reference gate for cross-service Protect execution."""

    def __init__(self, protect_engine: ProtectEngine | None = None) -> None:
        self.protect_engine = protect_engine or ProtectEngine()
        self.replay_ledger = AuthorizationReplayLedger()

    def execute(
        self,
        policy_record: dict,
        authorization: ExecutionAuthorization,
        authority: ExecutorAuthority,
        *,
        signing_key: bytes,
        handler: Callable[[str, dict], bool] | None = None,
        now: datetime | None = None,
    ) -> AuthorizedExecutionResult:
        verification = verify_execution_authorization(
            authorization,
            policy_record,
            signing_key=signing_key,
            expected_executor_id=authority.executor_id,
            replay_ledger=self.replay_ledger,
            now=now,
        )
        if not verification.accepted:
            return AuthorizedExecutionResult(verification, None)

        result = self.protect_engine.execute(
            policy_record,
            authority,
            idempotency_key=authorization.idempotency_key,
            handler=handler,
            now=now,
        )
        return AuthorizedExecutionResult(verification, result)
