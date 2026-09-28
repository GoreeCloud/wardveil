"""Reference Security Center 2.0 projection for Wardveil next-upgrade evidence.

This module is intentionally presentation-only. It consumes already-authoritative
Wardveil state/evidence and cannot create stronger security truth.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Mapping

SCHEMA_VERSION = "0.2.0"
GLAZE_UI_VERSION = "1.3.0"
GLAZE_UI_REVISION = "8354308445da9ac35ced2b37a7f503a08a0aaf72"
GLAZE_UI_ROLLBACK_VERSION = "1.2.0"

SECURITY_STATES = {
    "protected",
    "at_risk",
    "action_required",
    "unknown",
    "not_covered",
    "degraded",
    "contained",
    "recovering",
    "reconciliation_required",
}
COVERAGE_STATES = {"covered", "partial", "not_covered", "unknown", "stale", "degraded"}
AREAS = (
    "protection",
    "protection_coverage",
    "threats",
    "quarantine",
    "incidents",
    "sessions_and_devices",
    "application_access",
    "security_policies",
    "recommendations",
    "security_evidence",
    "audit_history",
    "recovery_verification",
)
APPEARANCES = {"light", "dark", "deep_dark"}


def _parse_time(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("timestamp must be a non-empty string")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    try:
        return parsed.astimezone(timezone.utc)
    except OverflowError as error:
        raise ValueError("timestamp is outside the supported UTC range") from error


def _bounded_text(value: Any, name: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    value = value.strip()
    if len(value) > limit:
        raise ValueError(f"{name} exceeds {limit} characters")
    credential_markers = (
        "authorization: bearer ",
        "private_key",
        "client_secret",
        "password=",
        "session_token=",
        "api_key=",
    )
    private_content_markers = (
        "cookie:",
        "set-cookie:",
        "request_body=",
        "raw_private_content=",
        "raw_private_activity=",
        "visited_url=",
        "search_query=",
        "dns_query=",
        "recovery_code=",
        "unrestricted_diagnostic_payload=",
    )
    lowered = value.lower()
    if any(marker in lowered for marker in credential_markers):
        raise ValueError(f"{name} contains reusable credential material")
    if any(marker in lowered for marker in private_content_markers):
        raise ValueError(f"{name} contains private user content or unrestricted diagnostic material")
    return value


def _privacy_minimization(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("privacy_minimization must be an object")

    false_fields = (
        "raw_private_content_included",
        "raw_private_activity_included",
        "reusable_credentials_included",
        "recovery_material_included",
        "unrestricted_diagnostic_payloads_included",
    )
    required_fields = set(false_fields) | {"identifier_scope", "privacy_shield_review_required"}
    if set(value) != required_fields:
        raise ValueError("privacy_minimization fields must match the contract exactly")

    for field in false_fields:
        if value.get(field) is not False:
            raise ValueError(f"privacy_minimization.{field} must be false")
    if value.get("identifier_scope") != "necessary_bounded":
        raise ValueError("privacy_minimization.identifier_scope must be necessary_bounded")
    if value.get("privacy_shield_review_required") is not True:
        raise ValueError("privacy_minimization.privacy_shield_review_required must be true")

    return {
        "raw_private_content_included": False,
        "raw_private_activity_included": False,
        "reusable_credentials_included": False,
        "recovery_material_included": False,
        "unrestricted_diagnostic_payloads_included": False,
        "identifier_scope": "necessary_bounded",
        "privacy_shield_review_required": True,
    }


def build_security_center_snapshot(
    security_record: Mapping[str, Any],
    coverage_record: Mapping[str, Any],
    *,
    appearance: str = "light",
    generated_at: str | None = None,
    accessibility: Mapping[str, bool] | None = None,
) -> dict[str, Any]:
    """Project authoritative Wardveil records into a conservative UI snapshot.

    `security_record` and `coverage_record` are treated as inputs, not rewritten
    authorities. The projection fails closed whenever current evidence cannot
    support the supplied state or claim authority.
    """
    security = deepcopy(dict(security_record))
    coverage = deepcopy(dict(coverage_record))

    state = security.get("security_state")
    if state not in SECURITY_STATES:
        raise ValueError("unsupported security state")
    coverage_state = coverage.get("coverage_state")
    if coverage_state not in COVERAGE_STATES:
        raise ValueError("unsupported coverage state")
    if appearance not in APPEARANCES:
        raise ValueError("unsupported appearance")

    resource_scope = _bounded_text(security.get("resource_scope"), "resource_scope", 256)
    if coverage.get("resource_scope") != resource_scope:
        raise ValueError("coverage scope does not match security scope")

    privacy_minimization = _privacy_minimization(security.get("privacy_minimization"))

    observed_at = _parse_time(security.get("observed_at"))
    valid_until_raw = security.get("valid_until")
    valid_until = _parse_time(valid_until_raw) if valid_until_raw else None
    generated = _parse_time(generated_at) if generated_at else datetime.now(timezone.utc)
    if observed_at > generated:
        raise ValueError("future-dated security evidence cannot be presented as current")
    evidence_valid = valid_until is not None and generated < valid_until

    producer = _bounded_text(security.get("producer"), "producer", 160)
    reason_code = _bounded_text(security.get("reason_code"), "reason_code", 128)
    summary = _bounded_text(security.get("summary"), "summary", 512)
    next_action = _bounded_text(security.get("next_action"), "next_action", 512)

    execution_requested = bool(security.get("protective_execution_requested", False))
    execution_verified = bool(security.get("protective_execution_verified", False))
    reconciliation_required = bool(security.get("reconciliation_required", False))
    requested_claim_authority = bool(security.get("claim_authority", False))

    claim_authority = requested_claim_authority
    if state == "protected":
        if not evidence_valid:
            claim_authority = False
        if coverage_state != "covered":
            claim_authority = False
        if not bool(coverage.get("production_accepted", False)):
            claim_authority = False
        if not execution_verified:
            claim_authority = False
        if reconciliation_required:
            claim_authority = False
    else:
        claim_authority = False

    presented_state = state
    presented_reason = reason_code
    presented_summary = summary
    if state == "protected" and not claim_authority:
        presented_state = "unknown"
        presented_reason = "security_center_protection_claim_unproven"
        presented_summary = "Required current evidence does not support a Protected by Wardveil claim for this scope."
    elif reconciliation_required and state not in {"reconciliation_required", "contained"}:
        presented_state = "reconciliation_required"
        presented_reason = "security_center_execution_uncertainty"
        presented_summary = "Execution outcome remains uncertain and must be reconciled before a stronger state can be shown."
    elif not evidence_valid and state not in {"unknown", "not_covered"}:
        presented_state = "unknown"
        presented_reason = "security_center_evidence_expired"
        presented_summary = "The most recent evidence is historical or expired and cannot justify a current security state."

    flags = dict(accessibility or {})
    presentation = {
        "glaze_ui_version": GLAZE_UI_VERSION,
        "glaze_ui_revision": GLAZE_UI_REVISION,
        "rollback_version": GLAZE_UI_ROLLBACK_VERSION,
        "appearance": appearance,
        "responsive": True,
        "reduced_transparency": bool(flags.get("reduced_transparency", False)),
        "reduced_motion": bool(flags.get("reduced_motion", False)),
        "increased_contrast": bool(flags.get("increased_contrast", False)),
        "forced_colors": bool(flags.get("forced_colors", False)),
        "touch_assistance": bool(flags.get("touch_assistance", False)),
        "material_fallback": True,
        "performance_fallback": True,
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated.isoformat().replace("+00:00", "Z"),
        "resource_scope": resource_scope,
        "security_state": presented_state,
        "coverage_state": coverage_state,
        "claim_authority": claim_authority,
        "privacy_minimization": privacy_minimization,
        "why_this_status": {
            "state": presented_state,
            "scope": resource_scope,
            "coverage": coverage_state,
            "reason_code": presented_reason,
            "producer": producer,
            "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
            "valid_until": valid_until.isoformat().replace("+00:00", "Z") if valid_until else None,
            "evidence_valid": evidence_valid,
            "protective_execution_requested": execution_requested,
            "protective_execution_verified": execution_verified,
            "reconciliation_required": reconciliation_required,
            "summary": presented_summary,
            "next_action": next_action,
        },
        "areas": list(AREAS),
        "presentation": presentation,
        "acceptance": {
            "source_validated": True,
            "rendered_visual_review": False,
            "accessibility_runtime": False,
            "live_evidence_consumption": False,
            "deployment_verified": False,
            "rollback_verified": False,
            "runtime_validated": False,
            "production_accepted": False,
            "stable_qualified": False,
        },
    }


def can_present_protected(snapshot: Mapping[str, Any]) -> bool:
    """Return true only for an exact protected snapshot with claim authority."""
    return snapshot.get("security_state") == "protected" and snapshot.get("claim_authority") is True
