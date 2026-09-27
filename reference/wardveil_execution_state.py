#!/usr/bin/env python3
"""Dependency-free Wardveil durable execution-state conformance reference.

This module models the state that a production Wardveil executor must persist
around a high-impact runtime authorization. It deliberately prefers an
operator-visible reconciliation state over replaying an action whose outcome
is uncertain.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from hashlib import sha256
import copy
import json
from typing import Callable

from reference.wardveil_protect import ExecutorAuthority, ProtectEngine, ProtectionResult
from reference.wardveil_runtime_authorization import (
    AuthorizationReplayLedger,
    ExecutionAuthorization,
    verify_execution_authorization,
)

EXECUTION_STATE_CONTRACT_VERSION = "0.1.0"
FINAL_OUTCOMES = {"succeeded", "rejected", "failed"}


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _utc(value: datetime | None = None) -> datetime:
    value = value or datetime.now(timezone.utc)
    if value.tzinfo is None:
        raise ValueError("timestamp_must_be_timezone_aware")
    try:
        return value.astimezone(timezone.utc)
    except OverflowError as error:
        raise ValueError("timestamp_out_of_supported_range") from error


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    try:
        return parsed.astimezone(timezone.utc)
    except OverflowError:
        return None


def authorization_digest(authorization: dict) -> str:
    return sha256(_canonical(authorization)).hexdigest()


@dataclass(frozen=True)
class ExecutionClaim:
    nonce: str
    authorization_id: str
    idempotency_key: str
    authorization_digest_sha256: str
    executor_id: str
    action: str
    correlation_id: str
    scope: dict
    claimed_at: str
    expires_at: str
    status: str = "claimed"


@dataclass(frozen=True)
class ExecutionReceipt:
    receipt_id: str
    nonce: str
    authorization_id: str
    authorization_digest_sha256: str
    executor_id: str
    action: str
    correlation_id: str
    scope: dict
    idempotency_key: str
    outcome: str
    protection_record: dict
    protection_record_digest_sha256: str
    completed_at: str
    receipt_digest_sha256: str

    def as_dict(self) -> dict:
        return {
            "contract_version": EXECUTION_STATE_CONTRACT_VERSION,
            "receipt_id": self.receipt_id,
            "nonce": self.nonce,
            "authorization_id": self.authorization_id,
            "authorization_digest_sha256": self.authorization_digest_sha256,
            "executor_id": self.executor_id,
            "action": self.action,
            "correlation_id": self.correlation_id,
            "scope": copy.deepcopy(self.scope),
            "idempotency_key": self.idempotency_key,
            "outcome": self.outcome,
            "protection_record": copy.deepcopy(self.protection_record),
            "protection_record_digest_sha256": self.protection_record_digest_sha256,
            "completed_at": self.completed_at,
            "receipt_digest_sha256": self.receipt_digest_sha256,
        }


@dataclass(frozen=True)
class ClaimDecision:
    status: str
    claim: ExecutionClaim | None = None
    receipt: ExecutionReceipt | None = None


@dataclass(frozen=True)
class CoordinatedExecutionResult:
    accepted: bool
    reason: str
    protection_result: ProtectionResult | None = None
    protection_record: dict | None = None
    receipt: ExecutionReceipt | None = None
    reconciliation_required: bool = False
    idempotent_replay: bool = False


class InMemoryExecutionStateStore:
    """Strong-semantics reference store; not a production durability claim."""

    def __init__(self) -> None:
        self._claims: dict[str, ExecutionClaim] = {}
        self._idempotency: dict[tuple[str, str], str] = {}
        self._receipts: dict[str, ExecutionReceipt] = {}

    def claim(self, authorization: dict, *, now: datetime | None = None) -> ClaimDecision:
        observed = _utc(now)
        required = (
            "authorization_id", "executor_id", "action", "correlation_id",
            "idempotency_key", "nonce", "issued_at", "expires_at", "scope",
        )
        if any(not authorization.get(key) for key in required):
            return ClaimDecision("invalid_authorization_state")
        if not isinstance(authorization.get("scope"), dict):
            return ClaimDecision("invalid_authorization_state")
        expires = _parse_time(authorization.get("expires_at"))
        if expires is None or expires <= observed:
            return ClaimDecision("expired_authorization")

        digest = authorization_digest(authorization)
        nonce = str(authorization["nonce"])
        authorization_id = str(authorization["authorization_id"])
        idempotency_key = str(authorization["idempotency_key"])
        executor_id = str(authorization["executor_id"])
        idem_identity = (executor_id, idempotency_key)

        existing = self._claims.get(nonce)
        if existing is not None:
            same = (
                existing.authorization_id == authorization_id
                and existing.idempotency_key == idempotency_key
                and existing.authorization_digest_sha256 == digest
                and existing.executor_id == executor_id
            )
            if not same:
                return ClaimDecision("authorization_nonce_conflict", existing)
            receipt = self._receipts.get(nonce)
            if receipt is not None:
                return ClaimDecision("idempotent_finalized", existing, receipt)
            return ClaimDecision("execution_reconciliation_required", existing)

        prior_nonce = self._idempotency.get(idem_identity)
        if prior_nonce is not None and prior_nonce != nonce:
            return ClaimDecision("executor_idempotency_conflict", self._claims.get(prior_nonce))

        claim = ExecutionClaim(
            nonce=nonce,
            authorization_id=authorization_id,
            idempotency_key=idempotency_key,
            authorization_digest_sha256=digest,
            executor_id=executor_id,
            action=str(authorization["action"]),
            correlation_id=str(authorization["correlation_id"]),
            scope=copy.deepcopy(authorization["scope"]),
            claimed_at=observed.isoformat(),
            expires_at=str(authorization["expires_at"]),
        )
        self._claims[nonce] = claim
        self._idempotency[idem_identity] = nonce
        return ClaimDecision("new", claim)

    def finalize(
        self,
        authorization: dict,
        protection_record: dict,
        *,
        now: datetime | None = None,
    ) -> ExecutionReceipt:
        observed = _utc(now)
        nonce = str(authorization.get("nonce") or "")
        claim = self._claims.get(nonce)
        if claim is None:
            raise ValueError("execution_claim_required")
        digest = authorization_digest(authorization)
        if digest != claim.authorization_digest_sha256:
            raise ValueError("authorization_claim_digest_mismatch")
        if authorization.get("authorization_id") != claim.authorization_id:
            raise ValueError("authorization_claim_identity_mismatch")

        outcome = protection_record.get("execution_status")
        if outcome not in FINAL_OUTCOMES:
            raise ValueError("invalid_protection_outcome")
        if protection_record.get("record_type") != "protection_action":
            raise ValueError("invalid_protection_record_type")
        producer = protection_record.get("producer") or {}
        if producer.get("authoritative") is not True or not producer.get("id"):
            raise ValueError("non_authoritative_protection_record")
        if protection_record.get("correlation_id") != claim.correlation_id:
            raise ValueError("protection_correlation_mismatch")
        if protection_record.get("policy_decision") != claim.action:
            raise ValueError("protection_action_mismatch")
        if protection_record.get("executor") != claim.executor_id:
            raise ValueError("protection_executor_mismatch")
        if protection_record.get("idempotency_key") != claim.idempotency_key:
            raise ValueError("protection_idempotency_mismatch")
        if protection_record.get("scope") != claim.scope:
            raise ValueError("protection_scope_mismatch")

        protection_digest = sha256(_canonical(protection_record)).hexdigest()
        existing = self._receipts.get(nonce)
        if existing is not None:
            if existing.protection_record_digest_sha256 != protection_digest or existing.outcome != outcome:
                raise ValueError("execution_receipt_conflict")
            return existing

        receipt_identity = {
            "authorization_digest_sha256": digest,
            "protection_record_digest_sha256": protection_digest,
            "outcome": outcome,
            "executor_id": claim.executor_id,
            "idempotency_key": claim.idempotency_key,
        }
        receipt_id = "exec-receipt-" + sha256(_canonical(receipt_identity)).hexdigest()[:32]
        receipt_body = {
            "contract_version": EXECUTION_STATE_CONTRACT_VERSION,
            "receipt_id": receipt_id,
            "nonce": nonce,
            "authorization_id": claim.authorization_id,
            "authorization_digest_sha256": digest,
            "executor_id": claim.executor_id,
            "action": claim.action,
            "correlation_id": claim.correlation_id,
            "scope": claim.scope,
            "idempotency_key": claim.idempotency_key,
            "outcome": outcome,
            "protection_record": protection_record,
            "protection_record_digest_sha256": protection_digest,
            "completed_at": observed.isoformat(),
        }
        receipt_digest = sha256(_canonical(receipt_body)).hexdigest()
        receipt = ExecutionReceipt(
            receipt_id=receipt_id,
            nonce=nonce,
            authorization_id=claim.authorization_id,
            authorization_digest_sha256=digest,
            executor_id=claim.executor_id,
            action=claim.action,
            correlation_id=claim.correlation_id,
            scope=copy.deepcopy(claim.scope),
            idempotency_key=claim.idempotency_key,
            outcome=str(outcome),
            protection_record=copy.deepcopy(protection_record),
            protection_record_digest_sha256=protection_digest,
            completed_at=observed.isoformat(),
            receipt_digest_sha256=receipt_digest,
        )
        self._receipts[nonce] = receipt
        self._claims[nonce] = replace(claim, status=str(outcome))
        return receipt

    def receipt(self, nonce: str) -> ExecutionReceipt | None:
        return self._receipts.get(nonce)


class DurableAuthorizedProtectCoordinator:
    """Reference orchestration for verify -> durable claim -> execute -> receipt."""

    def __init__(
        self,
        *,
        state_store: InMemoryExecutionStateStore | None = None,
        protect_engine: ProtectEngine | None = None,
    ) -> None:
        self.state_store = state_store or InMemoryExecutionStateStore()
        self.protect_engine = protect_engine or ProtectEngine()

    def execute(
        self,
        policy_record: dict,
        authorization: ExecutionAuthorization,
        authority: ExecutorAuthority,
        *,
        signing_key: bytes,
        handler: Callable[[str, dict], bool] | None = None,
        now: datetime | None = None,
    ) -> CoordinatedExecutionResult:
        observed = _utc(now)
        # A local replay ledger here is only part of cryptographic verification.
        # The durable state store below is the authoritative replay/idempotency
        # state for this orchestration path.
        verification = verify_execution_authorization(
            authorization,
            policy_record,
            signing_key=signing_key,
            expected_executor_id=authority.executor_id,
            replay_ledger=AuthorizationReplayLedger(),
            now=observed,
        )
        if not verification.accepted:
            return CoordinatedExecutionResult(False, verification.reason)

        claim = self.state_store.claim(authorization.as_dict(), now=observed)
        if claim.status == "idempotent_finalized":
            assert claim.receipt is not None
            return CoordinatedExecutionResult(
                True,
                "idempotent_finalized_execution",
                protection_record=copy.deepcopy(claim.receipt.protection_record),
                receipt=claim.receipt,
                idempotent_replay=True,
            )
        if claim.status == "execution_reconciliation_required":
            return CoordinatedExecutionResult(
                False,
                claim.status,
                reconciliation_required=True,
            )
        if claim.status != "new":
            return CoordinatedExecutionResult(False, claim.status)

        result = self.protect_engine.execute(
            policy_record,
            authority,
            idempotency_key=authorization.idempotency_key,
            handler=handler,
            now=observed,
        )
        protection_record = result.as_runtime_record(policy_record["correlation_id"])
        try:
            receipt = self.state_store.finalize(
                authorization.as_dict(),
                protection_record,
                now=observed,
            )
        except Exception:
            # The action may have happened. Do not authorize a blind retry.
            return CoordinatedExecutionResult(
                False,
                "execution_receipt_persistence_failed",
                protection_result=result,
                protection_record=protection_record,
                reconciliation_required=True,
            )
        return CoordinatedExecutionResult(
            True,
            "execution_finalized",
            protection_result=result,
            protection_record=protection_record,
            receipt=receipt,
        )
