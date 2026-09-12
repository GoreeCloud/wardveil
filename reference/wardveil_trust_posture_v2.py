"""Reference Wardveil v2 operation-scoped Trust, Session, and Device Posture model.

Trust is evidence for Policy, never execution authorization or target authority.
The evaluator prefers explicit uncertainty over a global or permanent trust label.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

SCHEMA_VERSION = "0.1.0"
TRUST_STATES = {
    "trusted",
    "restricted",
    "unknown",
    "untrusted",
    "reauthentication_required",
}
INPUT_STATES = {"present", "missing", "stale", "conflicting", "invalid"}
IMPACT_LEVELS = {"low", "medium", "high"}
HIGH_IMPACT_MAX_AGE_SECONDS = 300
DEFAULT_MAX_AGE_SECONDS = 900


def _parse_time(value: Any, name: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty timestamp")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _string(record: Mapping[str, Any], name: str, limit: int = 256) -> str:
    value = record.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    value = value.strip()
    if len(value) > limit:
        raise ValueError(f"{name} exceeds {limit} characters")
    return value


def evaluate_trust_posture(
    record: Mapping[str, Any], *, evaluated_at: str | None = None
) -> dict[str, Any]:
    """Evaluate bounded trust evidence for one exact operation.

    The result cannot authorize execution. Missing, stale, conflicting, invalid,
    revoked, compromised, or integrity-failed evidence fails closed.
    """
    subject_id = _string(record, "subject_id", 128)
    device_id = _string(record, "device_id", 128)
    session_id = _string(record, "session_id", 128)
    runtime_id = _string(record, "runtime_id", 128)
    application_id = _string(record, "application_id", 128)
    action = _string(record, "action", 160)
    impact = _string(record, "impact", 16)
    if impact not in IMPACT_LEVELS:
        raise ValueError("impact must be low, medium, or high")

    observed_at = _parse_time(record.get("observed_at"), "observed_at")
    expires_at = _parse_time(record.get("expires_at"), "expires_at")
    evaluated = _parse_time(evaluated_at, "evaluated_at") if evaluated_at else datetime.now(timezone.utc)
    if observed_at > evaluated:
        raise ValueError("observed_at cannot be later than evaluated_at")
    if expires_at <= observed_at:
        raise ValueError("expires_at must be later than observed_at")

    inputs = record.get("inputs")
    if not isinstance(inputs, list) or not inputs:
        raise ValueError("inputs must be a non-empty list")

    normalized_inputs: list[dict[str, Any]] = []
    seen: set[str] = set()
    reasons: list[str] = []
    for index, item in enumerate(inputs):
        if not isinstance(item, Mapping):
            raise ValueError(f"inputs[{index}] must be an object")
        input_id = _string(item, "id", 128)
        if input_id in seen:
            raise ValueError(f"duplicate trust input {input_id}")
        seen.add(input_id)
        state = _string(item, "state", 32)
        if state not in INPUT_STATES:
            raise ValueError(f"unsupported trust input state {state}")
        authority = _string(item, "authority", 128)
        evidence_reference = item.get("evidence_reference")
        if state == "present":
            if not isinstance(evidence_reference, str) or not evidence_reference.strip():
                raise ValueError(f"present trust input {input_id} requires evidence_reference")
            evidence_reference = evidence_reference.strip()
        elif evidence_reference is not None and not isinstance(evidence_reference, str):
            raise ValueError(f"trust input {input_id} evidence_reference must be a string or null")

        if state != "present":
            reasons.append(f"input_{state}:{input_id}")
        normalized_inputs.append(
            {
                "id": input_id,
                "state": state,
                "authority": authority,
                "evidence_reference": evidence_reference,
            }
        )

    triggers = record.get("reevaluation_triggers", {})
    if not isinstance(triggers, Mapping):
        raise ValueError("reevaluation_triggers must be an object")
    trigger_names = (
        "session_revoked",
        "credential_compromised",
        "runtime_integrity_failed",
        "material_posture_changed",
        "material_security_incident",
    )
    normalized_triggers: dict[str, bool] = {}
    for name in trigger_names:
        value = triggers.get(name, False)
        if not isinstance(value, bool):
            raise ValueError(f"reevaluation_triggers.{name} must be boolean")
        normalized_triggers[name] = value
        if value:
            reasons.append(name)

    age_seconds = (evaluated - observed_at).total_seconds()
    max_age_seconds = HIGH_IMPACT_MAX_AGE_SECONDS if impact == "high" else DEFAULT_MAX_AGE_SECONDS
    if evaluated >= expires_at:
        reasons.append("trust_evidence_expired")
    if age_seconds > max_age_seconds:
        reasons.append("trust_evidence_too_old_for_operation")

    proposed_state = _string(record, "proposed_state", 64)
    if proposed_state not in TRUST_STATES:
        raise ValueError("proposed_state is unsupported")

    hard_failure = any(
        normalized_triggers[name]
        for name in ("credential_compromised", "runtime_integrity_failed", "material_security_incident")
    ) or any(item["state"] in {"conflicting", "invalid"} for item in normalized_inputs)
    reauthentication = normalized_triggers["session_revoked"]
    insufficient = any(item["state"] in {"missing", "stale"} for item in normalized_inputs)
    stale = "trust_evidence_expired" in reasons or "trust_evidence_too_old_for_operation" in reasons

    if hard_failure:
        trust_state = "untrusted"
    elif reauthentication:
        trust_state = "reauthentication_required"
    elif insufficient or stale:
        trust_state = "unknown"
    elif normalized_triggers["material_posture_changed"]:
        trust_state = "restricted"
    else:
        trust_state = proposed_state

    # A caller cannot force a stronger state than the evaluator's fail-closed result.
    if proposed_state == "trusted" and trust_state != "trusted":
        reasons.append("proposed_trusted_state_not_supported")

    return {
        "schema_version": SCHEMA_VERSION,
        "evaluated_at": evaluated.isoformat().replace("+00:00", "Z"),
        "scope": {
            "subject_id": subject_id,
            "device_id": device_id,
            "session_id": session_id,
            "runtime_id": runtime_id,
            "application_id": application_id,
            "action": action,
            "impact": impact,
        },
        "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "inputs": normalized_inputs,
        "reevaluation_triggers": normalized_triggers,
        "trust_state": trust_state,
        "reason_codes": sorted(set(reasons)),
        "authorization_effect": False,
        "execution_authorization": False,
        "target_authority": False,
        "global_trust": False,
    }
