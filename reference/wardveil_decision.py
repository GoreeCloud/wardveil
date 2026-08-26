#!/usr/bin/env python3
"""Dependency-free Wardveil Trust + Policy reference engine.

This is a reference implementation for deterministic contract behavior. It is not
itself a production authentication or authorization service.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable
from uuid import uuid4

TRUST_STATES = ("trusted", "normal", "elevated_risk", "restricted", "blocked")
POLICY_DECISIONS = (
    "allow", "allow_and_log", "warn", "step_up", "restrict",
    "quarantine", "revoke", "block", "isolate", "escalate",
)


@dataclass(frozen=True)
class TrustSignal:
    name: str
    value: str | bool | int | float
    authoritative: bool = True
    risk_weight: int = 0
    evidence_ref: str | None = None


@dataclass(frozen=True)
class AccessRequest:
    principal_class: str
    resource_type: str
    resource_id: str
    operation: str
    producer_id: str
    signals: tuple[TrustSignal, ...] = field(default_factory=tuple)
    resource_sensitivity: str = "normal"
    requested_privilege: str = "standard"


@dataclass(frozen=True)
class TrustDecision:
    state: str
    reason_codes: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    observed_at: datetime
    valid_until: datetime

    def as_runtime_record(self, request: AccessRequest, correlation_id: str) -> dict:
        return {
            "contract_version": "0.1.0",
            "record_type": "trust_decision",
            "record_id": f"trust-{uuid4()}",
            "correlation_id": correlation_id,
            "producer": {"id": "wardveil-trust-reference", "authoritative": True},
            "scope": {
                "resource_type": request.resource_type,
                "resource_id": request.resource_id,
                "operation": request.operation,
                "principal_class": request.principal_class,
            },
            "observed_at": self.observed_at.isoformat(),
            "valid_until": self.valid_until.isoformat(),
            "evidence_refs": list(self.evidence_refs),
            "trust_state": self.state,
        }


@dataclass(frozen=True)
class PolicyDecision:
    decision: str
    reason_codes: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    observed_at: datetime
    valid_until: datetime

    def as_runtime_record(self, request: AccessRequest, correlation_id: str) -> dict:
        return {
            "contract_version": "0.1.0",
            "record_type": "policy_decision",
            "record_id": f"policy-{uuid4()}",
            "correlation_id": correlation_id,
            "producer": {"id": "wardveil-policy-reference", "authoritative": True},
            "scope": {
                "resource_type": request.resource_type,
                "resource_id": request.resource_id,
                "operation": request.operation,
                "principal_class": request.principal_class,
            },
            "observed_at": self.observed_at.isoformat(),
            "valid_until": self.valid_until.isoformat(),
            "evidence_refs": list(self.evidence_refs),
            "policy_decision": self.decision,
        }


def _now() -> datetime:
    return datetime.now(timezone.utc)


def evaluate_trust(request: AccessRequest, *, now: datetime | None = None) -> TrustDecision:
    observed_at = now or _now()
    reasons: list[str] = []
    evidence: list[str] = []

    if not request.signals:
        return TrustDecision(
            "restricted", ("missing_required_trust_evidence",), (),
            observed_at, observed_at + timedelta(minutes=2),
        )

    if any(not signal.authoritative for signal in request.signals):
        return TrustDecision(
            "restricted", ("unverified_trust_evidence",), (),
            observed_at, observed_at + timedelta(minutes=2),
        )

    risk = 0
    for signal in request.signals:
        risk += max(0, signal.risk_weight)
        if signal.risk_weight > 0:
            reasons.append(f"risk:{signal.name}")
        if signal.evidence_ref:
            evidence.append(signal.evidence_ref)

    values = {signal.name: signal.value for signal in request.signals}
    if values.get("credential_compromised") is True or values.get("confirmed_compromise") is True:
        state = "blocked"
        reasons.append("confirmed_compromise")
    elif values.get("device_integrity") in {"failed", "compromised"} or risk >= 80:
        state = "restricted"
        reasons.append("material_integrity_or_risk_failure")
    elif risk >= 40:
        state = "elevated_risk"
    elif risk > 0:
        state = "normal"
    else:
        state = "trusted"

    if not reasons:
        reasons.append("required_trust_evidence_satisfied")

    ttl_minutes = 2 if state in {"blocked", "restricted"} else 5 if state == "elevated_risk" else 10
    return TrustDecision(state, tuple(dict.fromkeys(reasons)), tuple(dict.fromkeys(evidence)), observed_at, observed_at + timedelta(minutes=ttl_minutes))


def evaluate_policy(
    request: AccessRequest,
    trust: TrustDecision,
    *,
    now: datetime | None = None,
) -> PolicyDecision:
    observed_at = now or _now()
    evidence = trust.evidence_refs
    reasons: list[str] = [f"trust:{trust.state}"]

    if trust.valid_until <= observed_at:
        decision = "block"
        reasons.append("expired_trust_decision")
    elif trust.state == "blocked":
        decision = "block"
    elif trust.state == "restricted":
        decision = "restrict"
    elif request.requested_privilege == "privileged" and trust.state != "trusted":
        decision = "step_up"
        reasons.append("privileged_operation_requires_trusted_state")
    elif request.resource_sensitivity == "high" and trust.state in {"normal", "elevated_risk"}:
        decision = "step_up"
        reasons.append("sensitive_resource_requires_stronger_verification")
    elif trust.state == "elevated_risk":
        decision = "warn"
    elif request.operation in {"delete", "rotate_secret", "change_authentication", "export_sensitive"}:
        decision = "allow_and_log" if trust.state == "trusted" else "step_up"
        reasons.append("sensitive_operation")
    else:
        decision = "allow"

    return PolicyDecision(
        decision,
        tuple(dict.fromkeys(reasons)),
        evidence,
        observed_at,
        min(trust.valid_until, observed_at + timedelta(minutes=5)),
    )


def decide(request: AccessRequest, *, now: datetime | None = None) -> tuple[TrustDecision, PolicyDecision]:
    observed_at = now or _now()
    trust = evaluate_trust(request, now=observed_at)
    policy = evaluate_policy(request, trust, now=observed_at)
    return trust, policy


def evidence_refs(signals: Iterable[TrustSignal]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(signal.evidence_ref for signal in signals if signal.evidence_ref))
