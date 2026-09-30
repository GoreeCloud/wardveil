#!/usr/bin/env python3
"""Validate Wardveil Foundation 0.9 runtime authorization invariants."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "wardveil.runtime-authorization.json"
REFERENCE = ROOT / "reference" / "wardveil_runtime_authorization.py"
DOC = ROOT / "docs/RUNTIME-AUTHORIZATION.md"
VERSION = ROOT / "VERSION"
IDENTITY = ROOT / "contracts" / "wardveil.identity.json"
CAPABILITIES = ROOT / "contracts" / "wardveil.capabilities.json"

FORBIDDEN_KEYS = {
    "password", "private_key", "access_token", "refresh_token", "session_token",
    "client_secret", "authorization_header", "cookie", "signing_key",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"Wardveil runtime authorization validation failed: {message}")


def walk_keys(value):
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key).lower()
            yield from walk_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_keys(child)


def main() -> None:
    for path in (CONTRACT, REFERENCE, DOC, VERSION, IDENTITY, CAPABILITIES):
        require(path.is_file(), f"missing required file: {path.relative_to(ROOT)}")

    version = VERSION.read_text(encoding="utf-8").strip()
    require(version == "0.9.0", "runtime authorization requires foundation 0.9.0")

    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    identity = json.loads(IDENTITY.read_text(encoding="utf-8"))
    capabilities = json.loads(CAPABILITIES.read_text(encoding="utf-8"))
    source = REFERENCE.read_text(encoding="utf-8")
    docs = DOC.read_text(encoding="utf-8").lower()

    require(contract.get("contract_version") == "0.1.0", "unexpected contract version")
    require(contract.get("foundation_version") == version, "contract foundation version mismatch")
    require(contract.get("component") == "Wardveil Runtime Execution Authorization", "unexpected component identity")

    applies = contract.get("applies_to") or {}
    require(applies.get("cross_service_protect_execution") is True, "cross-service Protect execution must be covered")
    require(set(applies.get("high_impact_actions") or []) == {"restrict", "quarantine", "revoke", "block", "isolate", "escalate"}, "high-impact action set drifted")

    invariants = contract.get("security_invariants") or {}
    for key in (
        "authoritative_policy_record_required",
        "exact_policy_digest_binding_required",
        "exact_action_binding_required",
        "exact_scope_binding_required",
        "exact_executor_binding_required",
        "authorization_must_not_outlive_policy",
        "future_dated_authorization_fails_closed",
        "expired_authorization_fails_closed",
        "invalid_signature_fails_closed",
        "replay_identity_required",
        "idempotent_retry_requires_same_authorization_nonce_and_idempotency_key",
        "nonce_reuse_with_different_authorization_fails_closed",
        "high_impact_execution_requires_authorized_handler",
    ):
        require(invariants.get(key) is True, f"missing security invariant: {key}")
    require(invariants.get("maximum_authorization_ttl_seconds") == 300, "authorization TTL limit must remain five minutes")
    require(invariants.get("policy_decision_alone_is_execution_authority") is False, "policy decision must not equal execution authority")
    require(invariants.get("authorization_transfers_underlying_resource_authority") is False, "authorization must not transfer target authority")

    privacy = contract.get("privacy") or {}
    require(privacy.get("data_minimization_required") is True, "data minimization must be required")
    require(privacy.get("raw_resource_content_required") is False, "raw content must not be required")
    require(privacy.get("reusable_credentials_allowed") is False, "reusable credentials must be prohibited")
    require(privacy.get("signing_secrets_allowed_in_authorization_envelope") is False, "signing secrets must be prohibited from envelopes")
    leaked = sorted(set(walk_keys(contract)) & FORBIDDEN_KEYS)
    require(not leaked, f"contract contains secret-bearing field names: {', '.join(leaked)}")

    crypto = contract.get("reference_cryptography") or {}
    require(crypto.get("algorithm") == "HMAC-SHA256-reference-only", "reference algorithm label must remain explicit")
    require(crypto.get("reference_algorithm_is_production_acceptance") is False, "reference cryptography must not imply production acceptance")

    production = contract.get("production_acceptance") or {}
    require(production.get("status") == "unaccepted", "source release must not claim production runtime acceptance")
    required_evidence = set(production.get("required_evidence") or [])
    for item in (
        "approved_production_key_management",
        "authenticated_authorization_transport",
        "durable_shared_replay_and_idempotency_ledger",
        "executor_identity_authentication",
        "authorized_high_impact_executor_integration",
        "audit_receipt_persistence",
        "failure_and_replay_runtime_tests",
    ):
        require(item in required_evidence, f"missing production acceptance requirement: {item}")

    identity_runtime = identity.get("runtime_authorization_contract") or {}
    require(identity.get("foundation_version") == version, "identity foundation version mismatch")
    require(identity_runtime.get("contract_version") == "0.1.0", "identity runtime authorization metadata missing")
    require(identity_runtime.get("high_impact_cross_service_execution_requires_authorization") is True, "identity must require authorization for high-impact cross-service execution")
    require(identity_runtime.get("production_runtime_status") == "unaccepted", "identity must preserve unaccepted runtime status")

    cross = capabilities.get("cross_cutting") or {}
    require(capabilities.get("foundation_version") == version, "capabilities foundation version mismatch")
    require(cross.get("high_impact_execution_requires_bound_authorization") is True, "capabilities must require bound execution authorization")
    require(cross.get("execution_authority_separated_from_policy_decision") is True, "capabilities must separate policy and execution authority")
    require(cross.get("replay_resistant_execution") is True, "capabilities must require replay-resistant execution")

    for token in (
        "hmac.compare_digest",
        "authorization.policy_digest_sha256 != expected_digest",
        "authorization.scope != policy_record.get(\"scope\")",
        "authorization.action != policy_record.get(\"policy_decision\")",
        "authorization.executor_id != expected_executor_id",
        "authorization_nonce_conflict",
        "idempotent_authorization_replay",
        "MAX_AUTHORIZATION_TTL = timedelta(minutes=5)",
        "self.protect_engine.execute",
    ):
        require(token in source, f"reference implementation missing invariant: {token}")

    for phrase in (
        "a policy decision is not, by itself, permission",
        "authorization may never outlive the policy decision",
        "reuse of the same nonce for different authorization material is rejected",
        "hmac-sha256-reference-only",
        "production acceptance",
        "goreecloud mesh remains the coordination and governance plane",
    ):
        require(phrase in docs, f"documentation missing required boundary: {phrase}")

    print("Wardveil Foundation 0.9 runtime execution authorization validation passed.")


if __name__ == "__main__":
    main()
