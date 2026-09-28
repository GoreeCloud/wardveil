#!/usr/bin/env python3
"""Evidence-bound reconciliation for uncertain Wardveil execution outcomes.

Reconciliation never invokes an executor and never reopens the original
execution authorization. It records an operator/evidence conclusion while the
original durable claim remains non-replayable.
"""
from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256

from reference.wardveil_execution_state import ExecutionClaim

RECONCILIATION_CONTRACT_VERSION = "0.1.0"
RECONCILIATION_OUTCOMES = {"succeeded", "failed", "not_executed", "unknown"}


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _utc(value: datetime | None = None) -> datetime:
    value = value or datetime.now(timezone.utc)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp_must_be_timezone_aware")
    try:
        return value.astimezone(timezone.utc)
    except OverflowError as error:
        raise ValueError("timestamp_out_of_supported_range") from error


@dataclass(frozen=True)
class ExecutionReconciliation:
    reconciliation_id: str
    nonce: str
    authorization_id: str
    authorization_digest_sha256: str
    executor_id: str
    action: str
    correlation_id: str
    scope: dict
    idempotency_key: str
    observed_outcome: str
    effective_execution_state: str
    evidence_ref: str
    actor_id: str
    reconciled_at: str
    resolved: bool
    new_authorization_required: bool

    def as_dict(self) -> dict:
        return {
            "contract_version": RECONCILIATION_CONTRACT_VERSION,
            "record_type": "execution_reconciliation",
            "reconciliation_id": self.reconciliation_id,
            "nonce": self.nonce,
            "authorization_id": self.authorization_id,
            "authorization_digest_sha256": self.authorization_digest_sha256,
            "executor_id": self.executor_id,
            "action": self.action,
            "correlation_id": self.correlation_id,
            "scope": copy.deepcopy(self.scope),
            "idempotency_key": self.idempotency_key,
            "observed_outcome": self.observed_outcome,
            "effective_execution_state": self.effective_execution_state,
            "evidence_ref": self.evidence_ref,
            "actor_id": self.actor_id,
            "reconciled_at": self.reconciled_at,
            "resolved": self.resolved,
            "new_authorization_required": self.new_authorization_required,
            "original_authorization_reusable": False,
            "executor_invoked": False,
        }


def reconcile_uncertain_execution(
    claim: ExecutionClaim,
    *,
    observed_outcome: str,
    evidence_ref: str,
    actor_id: str,
    now: datetime | None = None,
) -> ExecutionReconciliation:
    """Create a bounded reconciliation record for an uncertain durable claim."""
    if claim.status != "claimed":
        raise ValueError("reconciliation_requires_uncertain_claim")
    outcome = str(observed_outcome or "").strip()
    if outcome not in RECONCILIATION_OUTCOMES:
        raise ValueError("invalid_reconciliation_outcome")
    evidence = str(evidence_ref or "").strip()
    actor = str(actor_id or "").strip()
    if not evidence:
        raise ValueError("reconciliation_evidence_required")
    if not actor:
        raise ValueError("reconciliation_actor_required")

    reconciled_at = _utc(now).isoformat()
    resolved = outcome != "unknown"
    effective = outcome if resolved else "execution_reconciliation_required"
    new_authorization_required = outcome == "not_executed"
    identity = {
        "authorization_digest_sha256": claim.authorization_digest_sha256,
        "nonce": claim.nonce,
        "executor_id": claim.executor_id,
        "idempotency_key": claim.idempotency_key,
        "observed_outcome": outcome,
        "evidence_ref": evidence,
        "actor_id": actor,
        "reconciled_at": reconciled_at,
    }
    reconciliation_id = "exec-reconcile-" + sha256(_canonical(identity)).hexdigest()[:32]
    return ExecutionReconciliation(
        reconciliation_id=reconciliation_id,
        nonce=claim.nonce,
        authorization_id=claim.authorization_id,
        authorization_digest_sha256=claim.authorization_digest_sha256,
        executor_id=claim.executor_id,
        action=claim.action,
        correlation_id=claim.correlation_id,
        scope=copy.deepcopy(claim.scope),
        idempotency_key=claim.idempotency_key,
        observed_outcome=outcome,
        effective_execution_state=effective,
        evidence_ref=evidence,
        actor_id=actor,
        reconciled_at=reconciled_at,
        resolved=resolved,
        new_authorization_required=new_authorization_required,
    )
