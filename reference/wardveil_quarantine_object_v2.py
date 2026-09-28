#!/usr/bin/env python3
"""Wardveil next-upgrade durable Quarantine object reference model.

This source reference layers the next-upgrade quarantine lifecycle over the
existing Foundation execution/authorization architecture. It never performs a
real target mutation. It encodes the invariant that target-side verification is
required before successful quarantine or another security-sensitive mutation
can be represented as complete, and that uncertain side effects require
reconciliation rather than blind replay.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable
from uuid import uuid4

CONTRACT_VERSION = "0.1.0"

QUARANTINE_STATES = (
    "quarantine_pending",
    "isolation_requested",
    "isolation_executing",
    "verified_quarantined",
    "reconciliation_required",
    "release_pending",
    "released",
    "restore_pending",
    "restored",
    "rescan_pending",
    "escalated",
    "removal_pending",
    "removed",
    "failed",
)

SECURITY_SENSITIVE_ACTIONS = (
    "quarantine",
    "release",
    "restore",
    "remove",
    "delete",
    "rescan",
    "escalate",
    "recover",
)

PENDING_STATE_BY_ACTION = {
    "quarantine": "isolation_requested",
    "release": "release_pending",
    "restore": "restore_pending",
    "remove": "removal_pending",
    "rescan": "rescan_pending",
    "recover": "restore_pending",
}

SUCCESS_STATE_BY_ACTION = {
    "quarantine": "verified_quarantined",
    "release": "released",
    "restore": "restored",
    "remove": "removed",
    "rescan": "verified_quarantined",
    "recover": "restored",
}

ALLOWED_START_STATES = {
    "quarantine": {"quarantine_pending", "failed"},
    "release": {"verified_quarantined"},
    "restore": {"verified_quarantined", "released"},
    "remove": {"verified_quarantined", "released", "restored"},
    "rescan": {"verified_quarantined"},
    "escalate": set(QUARANTINE_STATES) - {"removed"},
    "recover": {"verified_quarantined", "released"},
}


def _utc(value: datetime | None = None) -> datetime:
    value = value or datetime.now(timezone.utc)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp_must_be_timezone_aware")
    try:
        return value.astimezone(timezone.utc)
    except OverflowError as error:
        raise ValueError("timestamp_out_of_supported_range") from error


def _require_text(value: str, field_name: str, max_length: int = 256) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise ValueError(f"{field_name}_required")
    if len(normalized) > max_length:
        raise ValueError(f"{field_name}_too_long")
    return normalized


def _refs(values: Iterable[str]) -> tuple[str, ...]:
    normalized = tuple(dict.fromkeys(str(value).strip() for value in values if str(value).strip()))
    if any(len(value) > 256 for value in normalized):
        raise ValueError("evidence_reference_too_long")
    return normalized


@dataclass(frozen=True)
class QuarantineTransition:
    sequence: int
    from_state: str | None
    to_state: str
    action: str
    observed_at: datetime
    reason: str
    evidence_refs: tuple[str, ...]
    authorization_ref: str | None = None

    def as_record(self) -> dict:
        return {
            "sequence": self.sequence,
            "from_state": self.from_state,
            "to_state": self.to_state,
            "action": self.action,
            **({"authorization_ref": self.authorization_ref} if self.authorization_ref else {}),
            "observed_at": self.observed_at.isoformat(),
            "reason": self.reason,
            "evidence_refs": list(self.evidence_refs),
        }


class QuarantineObject:
    """Durable reference state machine for one quarantinable target."""

    def __init__(
        self,
        *,
        correlation_id: str,
        target_authority: str,
        resource_type: str,
        resource_id: str,
        initiating_finding_ref: str,
        policy_decision_ref: str,
        quarantine_object_id: str | None = None,
        related_incident_ref: str | None = None,
        now: datetime | None = None,
    ) -> None:
        self.quarantine_object_id = _require_text(
            quarantine_object_id or f"quarantine-object-{uuid4()}", "quarantine_object_id", 160
        )
        self.correlation_id = _require_text(correlation_id, "correlation_id", 160)
        self.target_authority = _require_text(target_authority, "target_authority", 128)
        self.resource_type = _require_text(resource_type, "resource_type", 128)
        self.resource_id = _require_text(resource_id, "resource_id", 256)
        self.initiating_finding_ref = _require_text(initiating_finding_ref, "initiating_finding_ref")
        self.policy_decision_ref = _require_text(policy_decision_ref, "policy_decision_ref")
        self.related_incident_ref = (
            _require_text(related_incident_ref, "related_incident_ref") if related_incident_ref else None
        )

        self.state = "quarantine_pending"
        self.authorization_ref: str | None = None
        self.executor_id: str | None = None
        self.idempotency_key: str | None = None
        self.target_state_ref: str | None = None
        self.verified_resulting_state: str | None = None
        self.audit_refs: list[str] = []
        self.recovery_ref: str | None = None
        self.reconciliation_required = False
        self.reconciliation_reason: str | None = None
        self.reconciliation_evidence_ref: str | None = None
        self.pending_action: str | None = None
        self._state_before_action: str | None = None
        self.history: list[QuarantineTransition] = []
        self._append_transition(
            from_state=None,
            to_state="quarantine_pending",
            action="create",
            reason="quarantine_object_created",
            evidence_refs=(self.initiating_finding_ref, self.policy_decision_ref),
            now=now,
        )

    def _append_transition(
        self,
        *,
        from_state: str | None,
        to_state: str,
        action: str,
        reason: str,
        evidence_refs: Iterable[str] = (),
        authorization_ref: str | None = None,
        now: datetime | None = None,
    ) -> None:
        if to_state not in QUARANTINE_STATES:
            raise ValueError("unsupported_quarantine_state")
        self.history.append(
            QuarantineTransition(
                sequence=len(self.history) + 1,
                from_state=from_state,
                to_state=to_state,
                action=action,
                observed_at=_utc(now),
                reason=_require_text(reason, "transition_reason"),
                evidence_refs=_refs(evidence_refs),
                authorization_ref=(
                    _require_text(authorization_ref, "authorization_ref") if authorization_ref else None
                ),
            )
        )
        self.state = to_state

    def request_action(
        self,
        action: str,
        *,
        authorization_ref: str,
        executor_id: str,
        idempotency_key: str,
        evidence_refs: Iterable[str] = (),
        now: datetime | None = None,
    ) -> None:
        action = _require_text(action, "action", 64)
        if action not in SECURITY_SENSITIVE_ACTIONS:
            raise ValueError("unsupported_quarantine_action")
        if action == "delete":
            raise ValueError("destructive_delete_requires_separate_executor_contract")
        if self.reconciliation_required or self.state == "reconciliation_required":
            raise ValueError("reconciliation_must_complete_before_new_action")
        if self.pending_action is not None:
            raise ValueError("quarantine_action_already_pending")
        if self.state not in ALLOWED_START_STATES[action]:
            raise ValueError(f"action_not_allowed_from_state:{action}:{self.state}")

        auth = _require_text(authorization_ref, "authorization_ref")
        executor = _require_text(executor_id, "executor_id", 128)
        idem = _require_text(idempotency_key, "idempotency_key")
        self._state_before_action = self.state
        self.pending_action = action
        self.authorization_ref = auth
        self.executor_id = executor
        self.idempotency_key = idem
        self.target_state_ref = None
        self.verified_resulting_state = None

        if action == "escalate":
            self._append_transition(
                from_state=self.state,
                to_state="escalated",
                action="escalate",
                reason="authorized_security_escalation_recorded",
                evidence_refs=evidence_refs,
                authorization_ref=auth,
                now=now,
            )
            self.pending_action = None
            self._state_before_action = None
            return

        self._append_transition(
            from_state=self.state,
            to_state=PENDING_STATE_BY_ACTION[action],
            action=action,
            reason=f"authorized_{action}_requested",
            evidence_refs=evidence_refs,
            authorization_ref=auth,
            now=now,
        )

    def mark_execution_started(
        self,
        *,
        evidence_ref: str,
        now: datetime | None = None,
    ) -> None:
        if self.pending_action != "quarantine" or self.state != "isolation_requested":
            raise ValueError("isolation_execution_start_requires_requested_quarantine")
        self._append_transition(
            from_state=self.state,
            to_state="isolation_executing",
            action="quarantine",
            reason="authorized_quarantine_execution_started",
            evidence_refs=(evidence_ref,),
            authorization_ref=self.authorization_ref,
            now=now,
        )

    def complete_action(
        self,
        *,
        target_state_ref: str,
        verified_resulting_state: str,
        evidence_refs: Iterable[str],
        audit_ref: str | None = None,
        recovery_ref: str | None = None,
        now: datetime | None = None,
    ) -> None:
        action = self.pending_action
        if action is None:
            raise ValueError("no_quarantine_action_pending")
        if action == "quarantine" and self.state not in {"isolation_requested", "isolation_executing"}:
            raise ValueError("quarantine_completion_requires_isolation_execution_state")
        if action != "quarantine" and self.state != PENDING_STATE_BY_ACTION[action]:
            raise ValueError("action_completion_requires_matching_pending_state")

        target_ref = _require_text(target_state_ref, "target_state_ref")
        resulting_state = _require_text(verified_resulting_state, "verified_resulting_state", 128)
        refs = _refs(evidence_refs)
        if not refs:
            raise ValueError("target_state_verification_evidence_required")

        self.target_state_ref = target_ref
        self.verified_resulting_state = resulting_state
        if audit_ref:
            normalized_audit = _require_text(audit_ref, "audit_ref")
            if normalized_audit not in self.audit_refs:
                self.audit_refs.append(normalized_audit)
        if recovery_ref:
            self.recovery_ref = _require_text(recovery_ref, "recovery_ref")

        self._append_transition(
            from_state=self.state,
            to_state=SUCCESS_STATE_BY_ACTION[action],
            action=action,
            reason=f"{action}_target_state_verified",
            evidence_refs=(*refs, target_ref),
            authorization_ref=self.authorization_ref,
            now=now,
        )
        self.pending_action = None
        self._state_before_action = None

    def mark_failed(
        self,
        *,
        reason: str,
        evidence_refs: Iterable[str] = (),
        now: datetime | None = None,
    ) -> None:
        action = self.pending_action
        if action is None:
            raise ValueError("no_quarantine_action_pending")
        self._append_transition(
            from_state=self.state,
            to_state="failed",
            action="fail",
            reason=reason,
            evidence_refs=evidence_refs,
            authorization_ref=self.authorization_ref,
            now=now,
        )
        self.pending_action = None
        self._state_before_action = None

    def mark_uncertain(
        self,
        *,
        reason: str,
        evidence_refs: Iterable[str] = (),
        now: datetime | None = None,
    ) -> None:
        if self.pending_action is None:
            raise ValueError("uncertain_outcome_requires_pending_action")
        self.reconciliation_required = True
        self.reconciliation_reason = _require_text(reason, "reconciliation_reason")
        self.reconciliation_evidence_ref = None
        self._append_transition(
            from_state=self.state,
            to_state="reconciliation_required",
            action="reconcile",
            reason=self.reconciliation_reason,
            evidence_refs=evidence_refs,
            authorization_ref=self.authorization_ref,
            now=now,
        )

    def reconcile(
        self,
        *,
        observed_outcome: str,
        evidence_ref: str,
        actor_id: str,
        target_state_ref: str | None = None,
        verified_resulting_state: str | None = None,
        now: datetime | None = None,
    ) -> None:
        if not self.reconciliation_required or self.state != "reconciliation_required":
            raise ValueError("reconciliation_not_required")
        action = self.pending_action
        if action is None:
            raise ValueError("reconciliation_missing_pending_action")
        outcome = _require_text(observed_outcome, "observed_outcome", 64)
        if outcome not in {"succeeded", "failed", "not_executed", "unknown"}:
            raise ValueError("invalid_reconciliation_outcome")
        evidence = _require_text(evidence_ref, "reconciliation_evidence_ref")
        actor = _require_text(actor_id, "reconciliation_actor_id", 128)
        self.reconciliation_evidence_ref = evidence

        if outcome == "unknown":
            self._append_transition(
                from_state=self.state,
                to_state="reconciliation_required",
                action="reconcile",
                reason=f"reconciliation_still_unknown:{actor}",
                evidence_refs=(evidence,),
                now=now,
            )
            return

        if outcome == "succeeded":
            if not target_state_ref or not verified_resulting_state:
                raise ValueError("successful_reconciliation_requires_target_state_verification")
            self.target_state_ref = _require_text(target_state_ref, "target_state_ref")
            self.verified_resulting_state = _require_text(
                verified_resulting_state, "verified_resulting_state", 128
            )
            destination = SUCCESS_STATE_BY_ACTION[action]
            reason = f"reconciled_{action}_target_state_verified:{actor}"
            refs = (evidence, self.target_state_ref)
        else:
            destination = "failed"
            reason = f"reconciled_{action}_{outcome}:{actor}"
            refs = (evidence,)

        self._append_transition(
            from_state=self.state,
            to_state=destination,
            action="reconcile",
            reason=reason,
            evidence_refs=refs,
            now=now,
        )
        self.reconciliation_required = False
        self.reconciliation_reason = None
        self.pending_action = None
        self._state_before_action = None

    def as_record(self) -> dict:
        return {
            "contract_version": CONTRACT_VERSION,
            "record_type": "quarantine_object",
            "quarantine_object_id": self.quarantine_object_id,
            "correlation_id": self.correlation_id,
            "target": {
                "authority": self.target_authority,
                "resource_type": self.resource_type,
                "resource_id": self.resource_id,
            },
            "state": self.state,
            "initiating_finding_ref": self.initiating_finding_ref,
            "policy_decision_ref": self.policy_decision_ref,
            **({"authorization_ref": self.authorization_ref} if self.authorization_ref else {}),
            **({"executor_id": self.executor_id} if self.executor_id else {}),
            **({"idempotency_key": self.idempotency_key} if self.idempotency_key else {}),
            **({"target_state_ref": self.target_state_ref} if self.target_state_ref else {}),
            **(
                {"verified_resulting_state": self.verified_resulting_state}
                if self.verified_resulting_state
                else {}
            ),
            **({"related_incident_ref": self.related_incident_ref} if self.related_incident_ref else {}),
            "audit_refs": list(self.audit_refs),
            **({"recovery_ref": self.recovery_ref} if self.recovery_ref else {}),
            "history": [transition.as_record() for transition in self.history],
            "reconciliation": {
                "required": self.reconciliation_required,
                **({"reason": self.reconciliation_reason} if self.reconciliation_reason else {}),
                **(
                    {"evidence_ref": self.reconciliation_evidence_ref}
                    if self.reconciliation_evidence_ref
                    else {}
                ),
                "original_authorization_reusable": False,
            },
        }
