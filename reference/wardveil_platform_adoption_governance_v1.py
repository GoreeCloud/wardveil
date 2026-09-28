"""Fail-closed Wardveil platform-adoption and repository-governance evaluator."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

SCHEMA_VERSION = "0.1.0"
ADOPTION_STATES = (
    "Planned",
    "Implemented",
    "Source Validated",
    "Runtime Validated",
    "Production Accepted",
)


def _timestamp(value: Any, name: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty timestamp")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware")
    try:
        return parsed.astimezone(timezone.utc)
    except OverflowError as error:
        raise ValueError(f"{name} is outside the supported UTC range") from error


def _bool(record: Mapping[str, Any], name: str) -> bool:
    value = record.get(name)
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be boolean")
    return value


def _text(record: Mapping[str, Any], name: str, limit: int = 256) -> str:
    value = record.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    value = value.strip()
    if len(value) > limit:
        raise ValueError(f"{name} exceeds {limit} characters")
    return value


def evaluate_platform_adoption_governance(
    record: Mapping[str, Any], *, evaluated_at: str | None = None
) -> dict[str, Any]:
    consumer = _text(record, "consumer", 128)
    contract_version = _text(record, "wardveil_contract_version", 64)
    requested_state = _text(record, "requested_adoption_state", 32)
    if requested_state not in ADOPTION_STATES:
        raise ValueError("unsupported adoption state")

    adoption = record.get("adoption_evidence")
    governance = record.get("repository_governance")
    if not isinstance(adoption, Mapping) or not isinstance(governance, Mapping):
        raise ValueError("adoption_evidence and repository_governance must be objects")

    applicable = record.get("applicable_capabilities")
    implemented = record.get("implemented_capabilities")
    if not isinstance(applicable, list) or not all(isinstance(x, str) and x.strip() for x in applicable):
        raise ValueError("applicable_capabilities must be a string list")
    if not isinstance(implemented, list) or not all(isinstance(x, str) and x.strip() for x in implemented):
        raise ValueError("implemented_capabilities must be a string list")
    applicable_set = set(x.strip() for x in applicable)
    implemented_set = set(x.strip() for x in implemented)
    if not implemented_set.issubset(applicable_set):
        raise ValueError("implemented capabilities must be applicable")

    evaluated = _timestamp(evaluated_at, "evaluated_at") if evaluated_at else datetime.now(timezone.utc)
    observed = _timestamp(governance.get("observed_at"), "observed_at")
    max_age = governance.get("max_age_seconds")
    if not isinstance(max_age, int) or isinstance(max_age, bool) or max_age < 1:
        raise ValueError("max_age_seconds must be a positive integer")
    governance_fresh = 0 <= (evaluated - observed).total_seconds() <= max_age

    stage_checks = {
        "Planned": True,
        "Implemented": _bool(adoption, "implementation_evidence_present"),
        "Source Validated": _bool(adoption, "source_validation_passed"),
        "Runtime Validated": _bool(adoption, "runtime_validation_passed"),
        "Production Accepted": _bool(adoption, "production_acceptance_recorded"),
    }
    requested_index = ADOPTION_STATES.index(requested_state)
    missing_stage_evidence = [
        state for state in ADOPTION_STATES[: requested_index + 1] if not stage_checks[state]
    ]

    capability_complete = applicable_set == implemented_set
    if requested_index >= ADOPTION_STATES.index("Implemented") and not capability_complete:
        missing_stage_evidence.append("applicable_capabilities_incomplete")

    live_observation_available = _bool(governance, "live_hosting_observation_available")
    repo_controls = (
        "pull_request_required",
        "required_checks_enforced",
        "current_head_or_stale_review_protection",
        "force_push_restricted",
        "branch_deletion_restricted",
        "admin_bypass_bounded",
    )
    governance_reasons: list[str] = []
    if not live_observation_available:
        governance_reasons.append("live_repository_governance_unverified")
    if not governance_fresh:
        governance_reasons.append("repository_governance_evidence_stale")
    if live_observation_available:
        for control in repo_controls:
            if not _bool(governance, control):
                governance_reasons.append(f"repository_control_missing:{control}")

    codeowners_applicable = _bool(governance, "codeowners_applicable")
    codeowners_present = _bool(governance, "codeowners_present")
    if codeowners_applicable and not codeowners_present:
        governance_reasons.append("codeowners_missing")

    repository_governance_verified = not governance_reasons
    adoption_state_accepted = not missing_stage_evidence
    production_accepted = (
        requested_state == "Production Accepted"
        and adoption_state_accepted
        and repository_governance_verified
    )

    reasons = [f"adoption_evidence_missing:{item}" for item in missing_stage_evidence]
    reasons.extend(governance_reasons)
    if requested_state != "Production Accepted":
        reasons.append("production_acceptance_not_requested")

    return {
        "schema_version": SCHEMA_VERSION,
        "evaluated_at": evaluated.isoformat().replace("+00:00", "Z"),
        "consumer": consumer,
        "wardveil_contract_version": contract_version,
        "requested_adoption_state": requested_state,
        "applicable_capabilities": sorted(applicable_set),
        "implemented_capabilities": sorted(implemented_set),
        "adoption": {
            "requested_state_evidence_complete": adoption_state_accepted,
            "production_accepted": production_accepted,
        },
        "repository_governance": {
            "live_observation_available": live_observation_available,
            "evidence_fresh": governance_fresh,
            "verified": repository_governance_verified,
        },
        "claim_authority": production_accepted,
        "reason_codes": sorted(set(reasons)),
    }
