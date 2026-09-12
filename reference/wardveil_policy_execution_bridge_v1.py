#!/usr/bin/env python3
"""Fail-closed bridge from Wardveil v2 Policy decisions to Foundation 0.9 execution authorization.

This module deliberately reuses the existing Foundation 0.9 runtime-authorization
wire contract. It does not create a second execution-authority format and does
not grant target-side resource authority.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import unicodedata
from typing import Any, Mapping

from reference.wardveil_policy_decision_v2 import evaluate_policy_decision
from reference.wardveil_runtime_authorization import (
    HIGH_IMPACT_ACTIONS,
    AuthorizationReplayLedger,
    AuthorizationVerification,
    ExecutionAuthorization,
    create_execution_authorization,
    verify_execution_authorization,
)

BRIDGE_CONTRACT_VERSION = "0.1.0"
BRIDGE_PRODUCER_ID = "wardveil-policy-v2-execution-bridge"
MAX_BRIDGE_TEXT = 1000
MAX_BRIDGE_EVIDENCE_REFS = 128


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _nonempty(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip()
        and len(value) <= MAX_BRIDGE_TEXT
        and not any(unicodedata.category(char).startswith("C") for char in value)
    )


def _normalized_obligation_evidence(
    obligations: list[str],
    obligation_evidence: Mapping[str, str] | None,
) -> dict[str, str]:
    evidence = dict(obligation_evidence or {})
    expected = set(obligations)
    if set(evidence) != expected:
        if expected - set(evidence):
            raise ValueError("policy_obligation_evidence_missing")
        raise ValueError("unexpected_policy_obligation_evidence")
    normalized: dict[str, str] = {}
    for obligation in obligations:
        reference = evidence.get(obligation)
        if not _nonempty(reference):
            raise ValueError("policy_obligation_evidence_invalid")
        normalized[obligation] = reference
    return normalized


def build_foundation_09_policy_record(
    policy_decision_v2: dict[str, Any],
    *,
    target_resource_type: str,
    evaluated_at: str,
    obligation_evidence: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Derive an exact-digest-bound Foundation 0.9 policy record from one v2 decision.

    Only currently usable v2 allow/allow-with-obligations outcomes can cross the
    bridge. The returned record remains a policy record, not execution authority.
    """
    if not _nonempty(target_resource_type):
        raise ValueError("target_resource_type_required")

    evaluation = evaluate_policy_decision(policy_decision_v2, evaluated_at=evaluated_at)
    if not evaluation["decision_usable"]:
        reasons = evaluation.get("reason_codes") or ["policy_decision_not_usable"]
        raise ValueError(f"policy_decision_not_usable:{reasons[0]}")
    if not evaluation["enforcement_allowed"]:
        raise ValueError(f"policy_decision_not_enforcement_allowed:{evaluation['decision']}")

    request = policy_decision_v2["request"]
    action = request["action"]
    if action not in HIGH_IMPACT_ACTIONS:
        raise ValueError("policy_request_action_not_high_impact")

    obligations = list(policy_decision_v2.get("obligations") or [])
    obligation_refs = _normalized_obligation_evidence(obligations, obligation_evidence)
    v2_digest = sha256(_canonical(policy_decision_v2)).hexdigest()

    evidence_refs: list[str] = []
    for reference in (
        list(policy_decision_v2.get("evidence_refs") or [])
        + list((policy_decision_v2.get("trust") or {}).get("evidence_refs") or [])
        + list(obligation_refs.values())
    ):
        if reference not in evidence_refs:
            evidence_refs.append(reference)
            if len(evidence_refs) > MAX_BRIDGE_EVIDENCE_REFS:
                raise ValueError("policy_evidence_reference_limit_exceeded")

    return {
        "contract_version": "0.1.0",
        "record_type": "policy_decision",
        "record_id": f"v2-bridge:{policy_decision_v2['decision_id']}",
        "correlation_id": policy_decision_v2["correlation_id"],
        "producer": {
            "id": BRIDGE_PRODUCER_ID,
            "authoritative": True,
        },
        "scope": {
            "resource_type": target_resource_type,
            "resource_id": request["target"],
            "purpose": request["purpose"],
            "scopes": list(request["scopes"]),
            "audiences": list(request["audiences"]),
            "v2_decision_id": policy_decision_v2["decision_id"],
        },
        "observed_at": policy_decision_v2["observed_at"],
        "valid_until": policy_decision_v2["valid_until"],
        "evidence_refs": evidence_refs,
        "policy_decision": action,
        "v2_binding": {
            "bridge_contract_version": BRIDGE_CONTRACT_VERSION,
            "decision_id": policy_decision_v2["decision_id"],
            "decision_digest_sha256": v2_digest,
            "decision": policy_decision_v2["decision"],
            "policy": dict(policy_decision_v2["policy"]),
            "actor": dict(policy_decision_v2["actor"]),
            "request": {
                "action": request["action"],
                "target": request["target"],
                "purpose": request["purpose"],
                "scopes": list(request["scopes"]),
                "audiences": list(request["audiences"]),
            },
            "trust": {
                "state": policy_decision_v2["trust"]["state"],
                "evidence_refs": list(policy_decision_v2["trust"]["evidence_refs"]),
            },
            "reason_codes": list(policy_decision_v2["reason_codes"]),
            "obligations": obligations,
            "obligation_evidence": obligation_refs,
            "revocation": dict(policy_decision_v2["revocation"]),
            "execution_boundary": dict(policy_decision_v2["execution_boundary"]),
        },
    }


def create_v2_bound_execution_authorization(
    policy_decision_v2: dict[str, Any],
    *,
    target_resource_type: str,
    evaluated_at: str,
    obligation_evidence: Mapping[str, str] | None,
    signing_key: bytes,
    signing_key_id: str,
    executor_id: str,
    idempotency_key: str,
    nonce: str,
    now: datetime | None = None,
    ttl: timedelta = timedelta(minutes=2),
) -> tuple[dict[str, Any], ExecutionAuthorization]:
    """Build the bridge record and mint the existing Foundation 0.9 authorization."""
    observed = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    policy_record = build_foundation_09_policy_record(
        policy_decision_v2,
        target_resource_type=target_resource_type,
        evaluated_at=evaluated_at,
        obligation_evidence=obligation_evidence,
    )
    authorization = create_execution_authorization(
        policy_record,
        signing_key=signing_key,
        signing_key_id=signing_key_id,
        executor_id=executor_id,
        idempotency_key=idempotency_key,
        nonce=nonce,
        now=observed,
        ttl=ttl,
    )
    return policy_record, authorization


def verify_v2_bound_execution_authorization(
    authorization: ExecutionAuthorization,
    policy_decision_v2: dict[str, Any],
    *,
    target_resource_type: str,
    evaluated_at: str,
    obligation_evidence: Mapping[str, str] | None,
    signing_key: bytes,
    expected_executor_id: str,
    replay_ledger: AuthorizationReplayLedger,
    now: datetime | None = None,
) -> AuthorizationVerification:
    """Rebuild the exact bridge record and verify the unchanged 0.9 authorization."""
    try:
        policy_record = build_foundation_09_policy_record(
            policy_decision_v2,
            target_resource_type=target_resource_type,
            evaluated_at=evaluated_at,
            obligation_evidence=obligation_evidence,
        )
    except ValueError as exc:
        return AuthorizationVerification(False, str(exc))

    return verify_execution_authorization(
        authorization,
        policy_record,
        signing_key=signing_key,
        expected_executor_id=expected_executor_id,
        replay_ledger=replay_ledger,
        now=now,
    )
