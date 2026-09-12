#!/usr/bin/env python3
"""Validate Wardveil next-upgrade security-state and coverage contract invariants."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

STATE_SCHEMA = ROOT / "contracts" / "wardveil.security-state.v2.schema.json"
COVERAGE_SCHEMA = ROOT / "contracts" / "wardveil.protection-coverage.v1.schema.json"
REFERENCE = ROOT / "reference" / "wardveil_security_state_v2.py"
REGISTRY_REFERENCE = ROOT / "reference" / "wardveil_protection_coverage_registry.py"
TEST = ROOT / "scripts" / "test_wardveil_security_state_v2.py"
REGISTRY_TEST = ROOT / "scripts" / "test_wardveil_protection_coverage_registry.py"

EXPECTED_STATES = {
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

EXPECTED_COVERAGE = {
    "covered",
    "partial",
    "not_covered",
    "unknown",
    "stale",
    "degraded",
}

EXPECTED_CAPABILITIES = {
    "authentication_protection",
    "authorization_enforcement",
    "session_protection",
    "device_trust",
    "malware_protection",
    "malicious_url_protection",
    "vulnerability_monitoring",
    "security_update_posture",
    "secret_protection",
    "network_exposure_controls",
    "runtime_integrity",
    "security_event_reporting",
    "audit_coverage",
    "recovery_security_verification",
}

EXPECTED_ADOPTION = {
    "planned",
    "implemented",
    "source_validated",
    "runtime_validated",
    "production_accepted",
}


def fail(message: str) -> None:
    raise SystemExit(f"ERROR: {message}")


def load(path: Path) -> dict:
    if not path.is_file():
        fail(f"missing required file: {path.relative_to(ROOT)}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {path.relative_to(ROOT)}: {exc}")


def require_equal(actual, expected, label: str) -> None:
    if actual != expected:
        fail(f"{label} mismatch: expected {expected!r}, got {actual!r}")


def main() -> None:
    state = load(STATE_SCHEMA)
    coverage = load(COVERAGE_SCHEMA)

    require_equal(state.get("$id"), "urn:goreecloud:wardveil:security-state:0.2.0", "state schema id")
    require_equal(
        state["properties"]["state"]["enum"],
        [
            "protected",
            "at_risk",
            "action_required",
            "unknown",
            "not_covered",
            "degraded",
            "contained",
            "recovering",
            "reconciliation_required",
        ],
        "security state vocabulary",
    )
    if set(state["properties"]["state"]["enum"]) != EXPECTED_STATES:
        fail("security state vocabulary is incomplete")
    if set(state["properties"]["coverage"]["properties"]["status"]["enum"]) != EXPECTED_COVERAGE:
        fail("security-state coverage vocabulary is incomplete")

    protected_rule = state["allOf"][0]["then"]["properties"]
    require_equal(protected_rule["coverage"]["properties"]["status"]["const"], "covered", "Protected coverage requirement")
    require_equal(protected_rule["evidence"]["properties"]["status"]["const"], "current", "Protected evidence requirement")
    require_equal(protected_rule["authority"]["properties"]["authoritative"]["const"], True, "Protected authority requirement")
    require_equal(protected_rule["claim"]["properties"]["protected_by_wardveil"]["const"], True, "Protected claim requirement")

    require_equal(coverage.get("$id"), "urn:goreecloud:wardveil:protection-coverage:0.2.0", "coverage schema id")
    if set(coverage["properties"]["coverage_state"]["enum"]) != EXPECTED_COVERAGE:
        fail("coverage state vocabulary is incomplete")
    if set(coverage["properties"]["capability"]["enum"]) != EXPECTED_CAPABILITIES:
        fail("coverage capability vocabulary is incomplete")
    if set(coverage["properties"]["adoption_state"]["enum"]) != EXPECTED_ADOPTION:
        fail("adoption lifecycle vocabulary is incomplete")

    for property_name in (
        "subject",
        "enforcement",
        "dependencies",
        "known_gaps",
        "remediation",
        "stable_qualification_impact",
    ):
        if property_name not in coverage["properties"]:
            fail(f"coverage contract missing registry field: {property_name}")

    for path in (REFERENCE, REGISTRY_REFERENCE, TEST, REGISTRY_TEST):
        if not path.is_file():
            fail(f"missing required implementation file: {path.relative_to(ROOT)}")

    reference_text = REFERENCE.read_text(encoding="utf-8")
    for token in (
        "LEGACY_PRESENTATION_MAP",
        "COVERAGE_PRECEDENCE",
        "_conservative_coverage_state",
        "_conflicting_evidence_ids",
        "required_evidence_identity_conflict",
        "reconciliation_required",
        "production_accepted",
        "no_authoritative_protection_verification",
        "required_evidence_stale",
        "coverage_evidence_stale",
        "effective_coverage_state",
        "required_evidence_scope_mismatch",
        "security assessment scope cannot be relabeled",
        "scope_kind: str",
        "scope_id: str",
    ):
        if token not in reference_text:
            fail(f"reference implementation missing required invariant token: {token}")

    test_text = TEST.read_text(encoding="utf-8")
    for token in (
        "valid evidence for a different scope must fail closed",
        "security assessment must reject record serialization under a different scope",
        "conflicting duplicate coverage must never become Protected regardless of input order",
        "duplicate coverage conflict resolution must be deterministic and conservative",
        "exact duplicate evidence replay must remain idempotent",
        "conflicting duplicate evidence IDs must fail closed regardless of input order",
        "evidence ID conflict resolution must be deterministic and explainable",
    ):
        if token not in test_text:
            fail(f"security-state tests missing exact-scope or conflict regression: {token}")

    registry_text = REGISTRY_REFERENCE.read_text(encoding="utf-8")
    for token in (
        "ProtectionCoverageRegistry",
        "older coverage evidence cannot overwrite",
        "conflicting coverage evidence",
        "stable_qualification_impact",
        "required_enforcement_points",
        "implemented_enforcement_points",
    ):
        if token not in registry_text:
            fail(f"coverage registry missing required invariant token: {token}")

    print("Wardveil next-upgrade security-state and coverage contracts validated.")


if __name__ == "__main__":
    main()