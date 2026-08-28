#!/usr/bin/env python3
"""Bounded Wardveil Quarantine high-impact executor reference.

The reference composes Foundation 0.9 service identity, signed execution
authorization, durable pre-execution claims, target-side idempotency/readback,
Quarantine state, Audit provenance, and Security Center-compatible records.
It does not delete content or claim production deployment.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Protocol

from reference.wardveil_execution_state import (
    ExecutionReceipt,
    InMemoryExecutionStateStore,
    authorization_digest,
)
from reference.wardveil_incident import Authority, AuditEvent, QuarantineRecord, Scope, append_audit_event, quarantine
from reference.wardveil_protect import ExecutorAuthority, ProtectionResult
from reference.wardveil_runtime_authorization import AuthorizationReplayLedger, ExecutionAuthorization
from reference.wardveil_service_identity import (
    ReferenceSigningKeyring,
    ServiceIdentityRegistry,
    verify_identity_bound_execution_authorization,
)

QUARANTINE_EXECUTOR_VERSION = "0.1.0"
QUARANTINE_ACTION = "quarantine"
TARGET_FINAL_STATES = {"applied", "already_applied"}
TARGET_KNOWN_FAILURES = {"failed"}
TARGET_UNCERTAIN_STATES = {"unknown"}


def _utc(value: datetime | None = None) -> datetime:
    observed = value or datetime.now(timezone.utc)
    if observed.tzinfo is None:
        raise ValueError("timestamp_must_be_timezone_aware")
    return observed.astimezone(timezone.utc)


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
class TargetQuarantineResult:
    status: str
    operation_id: str
    state_ref: str
    evidence_ref: str
    reason: str


class QuarantineTarget(Protocol):
    def apply_quarantine(
        self,
        *,
        scope: dict,
        operation_id: str,
        correlation_id: str,
    ) -> TargetQuarantineResult: ...

    def read_quarantine(self, *, scope: dict) -> TargetQuarantineResult | None: ...


class InMemoryQuarantineTarget:
    """Target-side idempotency/readback reference; not production isolation."""

    def __init__(self, allowed_resource_types: frozenset[str]) -> None:
        self.allowed_resource_types = allowed_resource_types
        self.states: dict[tuple[str, str], TargetQuarantineResult] = {}
        self.apply_calls = 0

    def apply_quarantine(
        self,
        *,
        scope: dict,
        operation_id: str,
        correlation_id: str,
    ) -> TargetQuarantineResult:
        self.apply_calls += 1
        resource_type = str(scope.get("resource_type") or "")
        resource_id = str(scope.get("resource_id") or "")
        if resource_type not in self.allowed_resource_types or not resource_id:
            return TargetQuarantineResult(
                "failed", operation_id, "", "target:unsupported", "target_resource_type_unsupported"
            )
        key = (resource_type, resource_id)
        existing = self.states.get(key)
        if existing is not None:
            if existing.operation_id == operation_id:
                return TargetQuarantineResult(
                    "already_applied", operation_id, existing.state_ref,
                    existing.evidence_ref, "target_quarantine_already_applied",
                )
            return TargetQuarantineResult(
                "failed", operation_id, existing.state_ref,
                existing.evidence_ref, "target_quarantine_conflict",
            )
        state_ref = f"quarantine-state:{resource_type}:{sha256(resource_id.encode('utf-8')).hexdigest()[:16]}"
        result = TargetQuarantineResult(
            "applied",
            operation_id,
            state_ref,
            f"evidence:{operation_id}",
            "target_quarantine_applied",
        )
        self.states[key] = result
        return result

    def read_quarantine(self, *, scope: dict) -> TargetQuarantineResult | None:
        key = (str(scope.get("resource_type") or ""), str(scope.get("resource_id") or ""))
        return self.states.get(key)


@dataclass(frozen=True)
class QuarantineExecutionResult:
    accepted: bool
    reason: str
    protection_record: dict | None = None
    quarantine_record: dict | None = None
    audit_record: dict | None = None
    receipt: ExecutionReceipt | None = None
    reconciliation_required: bool = False
    idempotent_replay: bool = False


class QuarantineExecutor:
    """Reference verify -> claim -> target mutation/readback -> receipt path."""

    def __init__(
        self,
        *,
        identities: ServiceIdentityRegistry,
        keyring: ReferenceSigningKeyring,
        state_store: InMemoryExecutionStateStore | None = None,
    ) -> None:
        self.identities = identities
        self.keyring = keyring
        self.state_store = state_store or InMemoryExecutionStateStore()

    def execute(
        self,
        policy_record: dict,
        authorization: ExecutionAuthorization,
        authority: ExecutorAuthority,
        *,
        target: QuarantineTarget,
        reason: str,
        now: datetime | None = None,
    ) -> QuarantineExecutionResult:
        observed = _utc(now)
        if authorization.action != QUARANTINE_ACTION or policy_record.get("policy_decision") != QUARANTINE_ACTION:
            return QuarantineExecutionResult(False, "quarantine_action_required")
        scope = policy_record.get("scope")
        if not isinstance(scope, dict) or not scope.get("resource_type") or not scope.get("resource_id"):
            return QuarantineExecutionResult(False, "invalid_target_scope")
        if not authority.authorizes(QUARANTINE_ACTION, str(scope["resource_type"])):
            return QuarantineExecutionResult(False, "executor_not_authorized")
        if authority.executor_id != authorization.executor_id:
            return QuarantineExecutionResult(False, "executor_binding_mismatch")
        if not isinstance(reason, str) or not reason.strip() or len(reason.strip()) > 256:
            return QuarantineExecutionResult(False, "bounded_quarantine_reason_required")

        verification = verify_identity_bound_execution_authorization(
            authorization,
            policy_record,
            identities=self.identities,
            keyring=self.keyring,
            replay_ledger=AuthorizationReplayLedger(),
            now=observed,
        )
        if not verification.accepted:
            return QuarantineExecutionResult(False, verification.reason)

        claim = self.state_store.claim(authorization.as_dict(), now=observed)
        if claim.status == "idempotent_finalized":
            assert claim.receipt is not None
            return QuarantineExecutionResult(
                True,
                "idempotent_finalized_execution",
                protection_record=claim.receipt.protection_record,
                receipt=claim.receipt,
                idempotent_replay=True,
            )
        if claim.status == "execution_reconciliation_required":
            return QuarantineExecutionResult(False, claim.status, reconciliation_required=True)
        if claim.status != "new":
            return QuarantineExecutionResult(False, claim.status)

        auth_dict = authorization.as_dict()
        auth_digest = authorization_digest(auth_dict)
        operation_id = f"wardveil-quarantine-{auth_digest[:32]}"
        target_result = target.apply_quarantine(
            scope=dict(scope),
            operation_id=operation_id,
            correlation_id=authorization.correlation_id,
        )
        if target_result.status in TARGET_UNCERTAIN_STATES:
            return QuarantineExecutionResult(
                False,
                "target_quarantine_outcome_unknown",
                reconciliation_required=True,
            )

        valid_until = _parse_time(policy_record.get("valid_until")) or observed
        policy_evidence = tuple(str(ref) for ref in (policy_record.get("evidence_refs") or ()) if ref)
        evidence_refs = tuple(dict.fromkeys((*policy_evidence, target_result.evidence_ref)))

        if target_result.status in TARGET_KNOWN_FAILURES:
            result = ProtectionResult(
                action=QUARANTINE_ACTION,
                status="failed",
                reason_codes=(target_result.reason,),
                evidence_refs=evidence_refs,
                executor_id=authority.executor_id,
                idempotency_key=authorization.idempotency_key,
                observed_at=observed,
                valid_until=valid_until,
                scope=dict(scope),
            )
            protection_record = result.as_runtime_record(authorization.correlation_id)
            try:
                receipt = self.state_store.finalize(auth_dict, protection_record, now=observed)
            except Exception:
                return QuarantineExecutionResult(
                    False,
                    "execution_receipt_persistence_failed",
                    protection_record=protection_record,
                    reconciliation_required=True,
                )
            audit = self._audit(
                authorization,
                scope,
                receipt,
                target_result,
                outcome="failure",
                observed=observed,
            )
            return QuarantineExecutionResult(
                False,
                "target_quarantine_failed",
                protection_record=protection_record,
                audit_record=audit.as_runtime_record(),
                receipt=receipt,
            )

        if target_result.status not in TARGET_FINAL_STATES:
            return QuarantineExecutionResult(False, "unsupported_target_quarantine_result", reconciliation_required=True)
        readback = target.read_quarantine(scope=dict(scope))
        if (
            readback is None
            or readback.operation_id != operation_id
            or readback.status not in TARGET_FINAL_STATES
            or not readback.state_ref
        ):
            return QuarantineExecutionResult(
                False,
                "target_quarantine_readback_unverified",
                reconciliation_required=True,
            )

        result = ProtectionResult(
            action=QUARANTINE_ACTION,
            status="succeeded",
            reason_codes=(
                "authorized_executor_completed_action",
                "target_quarantine_state_readback_verified",
            ),
            evidence_refs=evidence_refs,
            executor_id=authority.executor_id,
            idempotency_key=authorization.idempotency_key,
            observed_at=observed,
            valid_until=valid_until,
            scope=dict(scope),
        )
        protection_record = result.as_runtime_record(authorization.correlation_id)
        try:
            receipt = self.state_store.finalize(auth_dict, protection_record, now=observed)
        except Exception:
            return QuarantineExecutionResult(
                False,
                "execution_receipt_persistence_failed",
                protection_record=protection_record,
                reconciliation_required=True,
            )

        q_scope = Scope(
            str(scope["resource_type"]),
            str(scope["resource_id"]),
            str(scope.get("operation")) if scope.get("operation") else None,
            str(scope.get("principal_class")) if scope.get("principal_class") else None,
        )
        quarantine_record = quarantine(
            record_id=f"quarantine-{auth_digest[:32]}",
            correlation_id=authorization.correlation_id,
            producer_id=authority.executor_id,
            scope=q_scope,
            reason=reason.strip(),
            evidence_refs=(*evidence_refs, receipt.receipt_id, readback.state_ref),
            source_record_ids=(policy_record["record_id"], protection_record["record_id"]),
            authority=Authority(authority.executor_id, frozenset({"quarantine"})),
            now=observed,
        )
        audit = self._audit(
            authorization,
            scope,
            receipt,
            readback,
            outcome="success",
            observed=observed,
            quarantine_record=quarantine_record,
        )
        return QuarantineExecutionResult(
            True,
            "quarantine_execution_finalized",
            protection_record=protection_record,
            quarantine_record=quarantine_record.as_runtime_record(),
            audit_record=audit.as_runtime_record(),
            receipt=receipt,
        )

    def _audit(
        self,
        authorization: ExecutionAuthorization,
        scope: dict,
        receipt: ExecutionReceipt,
        target_result: TargetQuarantineResult,
        *,
        outcome: str,
        observed: datetime,
        quarantine_record: QuarantineRecord | None = None,
    ) -> AuditEvent:
        q_scope = Scope(
            str(scope["resource_type"]),
            str(scope["resource_id"]),
            str(scope.get("operation")) if scope.get("operation") else None,
            str(scope.get("principal_class")) if scope.get("principal_class") else None,
        )
        refs = [receipt.receipt_id, target_result.evidence_ref]
        if quarantine_record is not None:
            refs.append(quarantine_record.record_id)
        return append_audit_event(
            record_id=f"audit-quarantine-{receipt.receipt_id.removeprefix('exec-receipt-')}",
            correlation_id=authorization.correlation_id,
            producer_id="wardveil-audit-runtime",
            scope=q_scope,
            event_type="quarantine.execution",
            outcome=outcome,
            actor_id=authorization.executor_id,
            evidence_refs=refs,
            authorization_provenance={
                "authorization_id": authorization.authorization_id,
                "issuer_id": authorization.issuer_id,
                "executor_id": authorization.executor_id,
                "signing_key_id": authorization.signing_key_id,
                "signature_algorithm": authorization.signature_algorithm,
            },
            now=observed,
        )
