#!/usr/bin/env python3
"""Dependency-free Wardveil Protect reference executor.

This module demonstrates the execution boundary between an authoritative Wardveil
Policy decision and a concrete protection executor. It performs no external
security mutation by itself.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable
from uuid import uuid4

POLICY_ACTIONS = {
    "allow", "allow_and_log", "warn", "step_up", "restrict",
    "quarantine", "revoke", "block", "isolate", "escalate",
}
HIGH_IMPACT_ACTIONS = {"restrict", "quarantine", "revoke", "block", "isolate", "escalate"}


@dataclass(frozen=True)
class ExecutorAuthority:
    executor_id: str
    allowed_actions: frozenset[str]
    allowed_resource_types: frozenset[str] = field(default_factory=frozenset)

    def authorizes(self, action: str, resource_type: str) -> bool:
        if action not in self.allowed_actions:
            return False
        return not self.allowed_resource_types or resource_type in self.allowed_resource_types


@dataclass(frozen=True)
class ProtectionResult:
    action: str
    status: str
    reason_codes: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    executor_id: str
    idempotency_key: str
    observed_at: datetime
    valid_until: datetime
    scope: dict

    def as_runtime_record(self, correlation_id: str) -> dict:
        return {
            "contract_version": "0.1.0",
            "record_type": "protection_action",
            "record_id": f"protect-{uuid4()}",
            "correlation_id": correlation_id,
            "producer": {"id": "wardveil-protect-reference", "authoritative": True},
            "scope": dict(self.scope),
            "observed_at": self.observed_at.isoformat(),
            "valid_until": self.valid_until.isoformat(),
            "evidence_refs": list(self.evidence_refs),
            "policy_decision": self.action,
            "executor": self.executor_id,
            "idempotency_key": self.idempotency_key,
            "execution_status": self.status,
        }


class ProtectEngine:
    """Reference executor with fail-closed validation and replay protection."""

    def __init__(self) -> None:
        self._results: dict[str, ProtectionResult] = {}

    def execute(
        self,
        policy_record: dict,
        authority: ExecutorAuthority,
        *,
        idempotency_key: str,
        handler: Callable[[str, dict], bool] | None = None,
        now: datetime | None = None,
    ) -> ProtectionResult:
        observed_at = now or datetime.now(timezone.utc)
        safe_key = idempotency_key.strip() if isinstance(idempotency_key, str) else ""

        if safe_key and safe_key in self._results:
            return self._results[safe_key]

        action = policy_record.get("policy_decision")
        scope = policy_record.get("scope")
        evidence_refs = tuple(policy_record.get("evidence_refs") or ())
        valid_until = _parse_time(policy_record.get("valid_until"))
        reasons: list[str] = []

        if not safe_key:
            return _rejected(action, scope, evidence_refs, authority, observed_at, "missing_idempotency_key", "missing-idempotency-key", valid_until)
        if policy_record.get("record_type") != "policy_decision":
            return self._remember(safe_key, _rejected(action, scope, evidence_refs, authority, observed_at, "invalid_policy_record_type", safe_key, valid_until))
        if policy_record.get("producer", {}).get("authoritative") is not True:
            return self._remember(safe_key, _rejected(action, scope, evidence_refs, authority, observed_at, "non_authoritative_policy_record", safe_key, valid_until))
        if action not in POLICY_ACTIONS:
            return self._remember(safe_key, _rejected(action, scope, evidence_refs, authority, observed_at, "unsupported_policy_action", safe_key, valid_until))
        if not isinstance(scope, dict) or not scope.get("resource_type") or not scope.get("resource_id"):
            return self._remember(safe_key, _rejected(action, scope, evidence_refs, authority, observed_at, "invalid_target_scope", safe_key, valid_until))
        if valid_until is None or valid_until <= observed_at:
            return self._remember(safe_key, _rejected(action, scope, evidence_refs, authority, observed_at, "expired_or_missing_policy_validity", safe_key, valid_until))
        if not authority.executor_id:
            return self._remember(safe_key, _rejected(action, scope, evidence_refs, authority, observed_at, "missing_executor_identity", safe_key, valid_until))
        if not authority.authorizes(action, scope["resource_type"]):
            return self._remember(safe_key, _rejected(action, scope, evidence_refs, authority, observed_at, "executor_not_authorized", safe_key, valid_until))
        if action in HIGH_IMPACT_ACTIONS and handler is None:
            return self._remember(safe_key, _rejected(action, scope, evidence_refs, authority, observed_at, "missing_execution_handler", safe_key, valid_until))

        if action in {"allow", "allow_and_log", "warn", "step_up"} and handler is None:
            succeeded = True
            reasons.append("non_mutating_reference_action")
        else:
            try:
                succeeded = bool(handler(action, dict(scope))) if handler else False
            except Exception:
                succeeded = False
                reasons.append("executor_exception")

        status = "succeeded" if succeeded else "failed"
        if succeeded:
            reasons.append("authorized_executor_completed_action")
        elif not reasons:
            reasons.append("executor_reported_failure")

        result = ProtectionResult(
            action=action,
            status=status,
            reason_codes=tuple(reasons),
            evidence_refs=evidence_refs,
            executor_id=authority.executor_id,
            idempotency_key=safe_key,
            observed_at=observed_at,
            valid_until=valid_until,
            scope=dict(scope),
        )
        return self._remember(safe_key, result)

    def _remember(self, key: str, result: ProtectionResult) -> ProtectionResult:
        self._results[key] = result
        return result


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


def _rejected(
    action: object,
    scope: object,
    evidence_refs: tuple[str, ...],
    authority: ExecutorAuthority,
    observed_at: datetime,
    reason: str,
    idempotency_key: str,
    valid_until: datetime | None = None,
) -> ProtectionResult:
    safe_scope = dict(scope) if isinstance(scope, dict) else {"resource_type": "unknown", "resource_id": "unknown"}
    safe_action = action if isinstance(action, str) and action else "block"
    return ProtectionResult(
        action=safe_action,
        status="rejected",
        reason_codes=(reason,),
        evidence_refs=evidence_refs,
        executor_id=authority.executor_id or "unassigned",
        idempotency_key=idempotency_key,
        observed_at=observed_at,
        valid_until=valid_until or observed_at,
        scope=safe_scope,
    )
