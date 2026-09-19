#!/usr/bin/env python3
"""Source validator for Wardveil Work Package I policy decision artifacts."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "contracts" / "wardveil.policy-decision.v2.schema.json"
REFERENCE = ROOT / "reference" / "wardveil_policy_decision_v2.py"
DOC = ROOT / "POLICY-DECISION-AND-ENFORCEMENT-V2.md"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    reference = REFERENCE.read_text(encoding="utf-8")
    documentation = DOC.read_text(encoding="utf-8")

    require(schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema", "unexpected schema dialect")
    require(schema.get("additionalProperties") is False, "top-level contract must reject unknown fields")
    decisions = schema["properties"]["decision"]["enum"]
    require(decisions == ["allow", "deny", "allow_with_obligations", "require_step_up", "defer", "unknown"], "decision vocabulary drift")
    boundary = schema["properties"]["execution_boundary"]["properties"]
    require(boundary["execution_authorization_required"].get("const") is True, "execution authorization must remain required")
    require(boundary["policy_decision_is_execution_authorization"].get("const") is False, "Policy must not become execution authorization")
    require(boundary["policy_decision_proves_execution_success"].get("const") is False, "Policy must not prove execution")

    required_reference_literals = [
        '"allow_with_obligations"',
        '"require_step_up"',
        '"defer"',
        '"unknown"',
        "conditional_allow_requires_obligations",
        "decision_revoked",
        "decision_expired",
        "policy_decision_cannot_be_execution_authorization",
        "policy_decision_cannot_prove_execution_success",
        '"quarantine": ("defer", ("route_to_authorized_response_path",))',
        '"allow_and_log": ("allow_with_obligations", ("audit_event_required",))',
        '"execution_authority": False',
    ]
    for literal in required_reference_literals:
        require(literal in reference, f"reference model missing invariant: {literal}")

    required_doc_literals = [
        "A Wardveil Policy decision is not execution authorization.",
        "Unknown and Defer are not aliases for Allow.",
        "Missing, malformed, stale, expired, revoked, unbound, or otherwise insufficient decision evidence fails closed.",
        "Foundation 0.9 compatibility",
        "Security Center",
        "This Work Package I milestone is source-level development only.",
        "Protected by Wardveil",
    ]
    for literal in required_doc_literals:
        require(literal in documentation, f"documentation missing boundary: {literal}")

    forbidden_claims = [
        "Work Package I is production accepted",
        "Policy decisions authorize execution directly",
        "production_acceptance: true",
    ]
    for claim in forbidden_claims:
        require(claim not in documentation, f"unsupported claim found: {claim}")

    print("validated Wardveil Policy Decision and Enforcement source contract")


if __name__ == "__main__":
    main()
