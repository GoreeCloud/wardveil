#!/usr/bin/env python3
"""Wardveil next-upgrade Policy Decision and Enforcement reference model.

This module is dependency-free source-level conformance logic. It does not mint
execution authorization and does not prove that any external side effect ran.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

CONTRACT_VERSION = "0.1.0"
RECORD_TYPE = "policy_decision"
DECISIONS = (
    "allow",
    "deny",
    "allow_with_obligations",
    "require_step_up",
    "defer",
    "unknown",
)
REVOCATION_STATES = ("active", "revoked")
FOUNDATION_09_COMPATIBILITY = {
    "allow": ("allow", ()),
    "allow_and_log": ("allow_with_obligations", ("audit_event_required",)),
    "warn": ("allow_with_obligations", ("user_warning_required",)),
    "step_up": ("require_step_up", ("stronger_evidence_required",)),
    "restrict": ("deny", ()),
    "revoke": ("deny", ()),
    "block": ("deny", ()),
    "quarantine": ("defer", ("route_to_authorized_response_path",)),
    "isolate": ("defer", ("route_to_authorized_response_path",)),
    "escalate": ("defer", ("route_to_authorized_response_path",)),
}


def _parse_time(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("timestamp must be a non-empty string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed.astimezone(timezone.utc)


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _unique_nonempty_strings(value: Any) -> bool:
    return (
        isinstance(value, list)
        and all(_nonempty(item) for item in value)
        and len(value) == len(set(value))
    )


def _valid_uuid(value: Any) -> bool:
    try:
        UUID(str(value))
        return True
    except (ValueError, TypeError, AttributeError):
        return False


def evaluate_policy_decision(record: dict[str, Any], *, evaluated_at: str) -> dict[str, Any]:
    """Evaluate one durable Policy decision conservatively and fail closed."""
    reasons: list[str] = []
    try:
        now = _parse_time(evaluated_at)
    except ValueError:
        now = datetime.max.replace(tzinfo=timezone.utc)
        reasons.append("evaluation_time_invalid")

    if record.get("contract_version") != CONTRACT_VERSION:
        reasons.append("contract_version_mismatch")
    if record.get("record_type") != RECORD_TYPE:
        reasons.append("record_type_mismatch")
    if not _valid_uuid(record.get("decision_id")):
        reasons.append("decision_id_invalid")
    if not _nonempty(record.get("correlation_id")):
        reasons.append("correlation_id_missing")

    policy = record.get("policy")
    if not isinstance(policy, dict):
        reasons.append("policy_binding_missing")
        policy = {}
    for field in ("policy_id", "policy_version", "policy_digest"):
        if not _nonempty(policy.get(field)):
            reasons.append(f"policy_{field}_missing")

    actor = record.get("actor")
    if not isinstance(actor, dict):
        reasons.append("actor_binding_missing")
        actor = {}
    if not (_nonempty(actor.get("subject_id")) or _nonempty(actor.get("service_id"))):
        reasons.append("actor_identity_missing")

    request = record.get("request")
    if not isinstance(request, dict):
        reasons.append("request_binding_missing")
        request = {}
    for field in ("action", "target", "purpose"):
        if not _nonempty(request.get(field)):
            reasons.append(f"request_{field}_missing")
    for field in ("scopes", "audiences"):
        if not _unique_nonempty_strings(request.get(field)):
            reasons.append(f"request_{field}_invalid")

    trust = record.get("trust")
    if not isinstance(trust, dict):
        reasons.append("trust_binding_missing")
        trust = {}
    if not _nonempty(trust.get("state")):
        reasons.append("trust_state_missing")
    if not _unique_nonempty_strings(trust.get("evidence_refs")):
        reasons.append("trust_evidence_refs_invalid")

    decision = record.get("decision")
    if decision not in DECISIONS:
        reasons.append("decision_outcome_invalid")
        decision = "unknown"

    reason_codes = record.get("reason_codes")
    if not _unique_nonempty_strings(reason_codes) or not reason_codes:
        reasons.append("reason_codes_invalid")
        reason_codes = []

    obligations = record.get("obligations")
    if not _unique_nonempty_strings(obligations):
        reasons.append("obligations_invalid")
        obligations = []
    if decision == "allow_with_obligations" and not obligations:
        reasons.append("conditional_allow_requires_obligations")

    evidence_refs = record.get("evidence_refs")
    if not _unique_nonempty_strings(evidence_refs) or not evidence_refs:
        reasons.append("evidence_refs_invalid")

    observed_at = valid_until = None
    try:
        observed_at = _parse_time(record.get("observed_at"))
        valid_until = _parse_time(record.get("valid_until"))
        if valid_until <= observed_at:
            reasons.append("decision_validity_window_invalid")
        if valid_until <= now:
            reasons.append("decision_expired")
        if observed_at > now:
            reasons.append("decision_from_future")
    except (ValueError, TypeError):
        reasons.append("decision_time_invalid")

    revocation = record.get("revocation")
    if not isinstance(revocation, dict):
        reasons.append("revocation_state_missing")
        revocation = {}
    revocation_state = revocation.get("state")
    if revocation_state not in REVOCATION_STATES:
        reasons.append("revocation_state_invalid")
    if revocation_state == "active":
        if revocation.get("reason_code") is not None or revocation.get("revoked_at") is not None:
            reasons.append("active_revocation_metadata_present")
    if revocation_state == "revoked":
        reasons.append("decision_revoked")
        if not _nonempty(revocation.get("reason_code")):
            reasons.append("revocation_reason_missing")
        try:
            revoked_at = _parse_time(revocation.get("revoked_at"))
            if observed_at is not None and revoked_at < observed_at:
                reasons.append("revocation_before_decision")
            if revoked_at > now:
                reasons.append("revocation_from_future")
        except (ValueError, TypeError):
            reasons.append("revocation_time_invalid")

    boundary = record.get("execution_boundary")
    if not isinstance(boundary, dict):
        reasons.append("execution_boundary_missing")
        boundary = {}
    if boundary.get("execution_authorization_required") is not True:
        reasons.append("execution_authorization_requirement_missing")
    if boundary.get("policy_decision_is_execution_authorization") is not False:
        reasons.append("policy_decision_cannot_be_execution_authorization")
    if boundary.get("policy_decision_proves_execution_success") is not False:
        reasons.append("policy_decision_cannot_prove_execution_success")

    decision_usable = not reasons
    enforcement_allowed = decision_usable and decision in {"allow", "allow_with_obligations"}
    step_up_required = decision_usable and decision == "require_step_up"
    must_defer = (not decision_usable) or decision in {"defer", "unknown"}
    denied = decision_usable and decision == "deny"

    return {
        "contract_version": CONTRACT_VERSION,
        "decision_id": record.get("decision_id"),
        "decision": decision,
        "decision_usable": decision_usable,
        "enforcement_allowed": enforcement_allowed,
        "step_up_required": step_up_required,
        "must_defer": must_defer,
        "denied": denied,
        "obligations": list(obligations or []),
        "execution_authorization_required": True,
        "execution_authority": False,
        "execution_success_proven": False,
        "reason_codes": reasons,
    }


def map_foundation_09_decision(decision: str) -> dict[str, Any]:
    """Conservatively map Foundation 0.9 presentation decisions into v2 semantics."""
    mapped, obligations = FOUNDATION_09_COMPATIBILITY.get(decision, ("unknown", ()))
    return {
        "foundation_decision": decision,
        "decision": mapped,
        "obligations": list(obligations),
        "execution_authorization_required": True,
        "execution_authority": False,
        "execution_success_proven": False,
    }
