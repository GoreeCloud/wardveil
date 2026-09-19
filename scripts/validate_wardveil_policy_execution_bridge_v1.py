#!/usr/bin/env python3
"""Validate the machine-readable Wardveil Policy-to-Execution bridge contract."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "wardveil.policy-execution-bridge.v1.json"


def main() -> None:
    data = json.loads(CONTRACT.read_text(encoding="utf-8"))
    assert data["contract_version"] == "0.1.0"
    assert data["work_package"] == "J"
    assert data["source_policy_contract"] == "contracts/wardveil.policy-decision.v2.schema.json"
    assert data["execution_authorization_contract"] == "contracts/wardveil.runtime-authorization.json"
    assert data["durable_execution_state_contract"] == "contracts/wardveil.execution-state.json"

    rules = data["bridge_rules"]
    assert rules["usable_policy_decision_required"] is True
    assert rules["allowed_policy_outcomes"] == ["allow", "allow_with_obligations"]
    assert set(rules["denied_policy_outcomes"]) == {"deny", "require_step_up", "defer", "unknown"}
    assert rules["high_impact_action_required"] is True
    assert rules["all_policy_obligations_require_evidence_before_authorization"] is True
    assert rules["exact_v2_decision_digest_preserved"] is True
    assert rules["foundation_09_authorization_wire_format_reused"] is True
    assert rules["authorization_must_not_outlive_v2_decision"] is True
    assert rules["policy_decision_is_execution_authorization"] is False
    assert rules["authorization_transfers_target_authority"] is False
    assert rules["authorization_proves_execution_success"] is False
    assert rules["target_executor_must_independently_authorize_action_and_resource"] is True
    assert rules["durable_claim_required_before_external_high_impact_execution_in_production"] is True
    assert rules["uncertain_outcome_requires_reconciliation"] is True
    assert rules["blind_reexecution_after_uncertain_outcome_allowed"] is False

    privacy = data["privacy"]
    assert privacy["data_minimization_required"] is True
    assert privacy["raw_resource_content_required"] is False
    assert privacy["reusable_credentials_allowed"] is False
    assert privacy["signing_secrets_allowed"] is False

    production = data["production_acceptance"]
    assert production["status"] == "unaccepted"
    assert production["source_validation_is_production_acceptance"] is False
    required = set(production["required_evidence"])
    for item in {
        "production_identity_and_signing_key_acceptance",
        "authorized_target_executor",
        "authoritative_target_state_readback",
        "uncertain_outcome_reconciliation",
        "privacy_shield_acceptance",
        "everkeep_recovery_acceptance",
    }:
        assert item in required

    print("Wardveil Policy-to-Execution bridge contract validated.")


if __name__ == "__main__":
    main()
