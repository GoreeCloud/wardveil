#!/usr/bin/env python3
"""Validate Wardveil Foundation 0.9 service identity and key lifecycle."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "wardveil.service-identity.json"
REFERENCE = ROOT / "reference" / "wardveil_service_identity.py"
RUNTIME_REFERENCE = ROOT / "reference" / "wardveil_runtime_authorization.py"
DOC = ROOT / "SERVICE-IDENTITY.md"
VERSION = ROOT / "VERSION"
IDENTITY = ROOT / "contracts" / "wardveil.identity.json"
RUNTIME_CONTRACT = ROOT / "contracts" / "wardveil.runtime-authorization.json"

FORBIDDEN_KEYS = {
    "password", "private_key", "access_token", "refresh_token", "session_token",
    "client_secret", "authorization_header", "cookie", "signing_key", "key_material",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"Wardveil service identity validation failed: {message}")


def walk_keys(value):
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key).lower()
            yield from walk_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_keys(child)


def main() -> None:
    for path in (CONTRACT, REFERENCE, RUNTIME_REFERENCE, DOC, VERSION, IDENTITY, RUNTIME_CONTRACT):
        require(path.is_file(), f"missing required file: {path.relative_to(ROOT)}")

    version = VERSION.read_text(encoding="utf-8").strip()
    require(version == "0.9.0", "service identity requires foundation 0.9.0")

    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    identity = json.loads(IDENTITY.read_text(encoding="utf-8"))
    runtime_contract = json.loads(RUNTIME_CONTRACT.read_text(encoding="utf-8"))
    reference = REFERENCE.read_text(encoding="utf-8")
    runtime_reference = RUNTIME_REFERENCE.read_text(encoding="utf-8")
    docs = DOC.read_text(encoding="utf-8").lower()

    require(contract.get("contract_version") == "0.1.0", "unexpected contract version")
    require(contract.get("foundation_version") == version, "foundation version mismatch")
    require(contract.get("component") == "Wardveil Service Identity and Signing Key Lifecycle", "unexpected component")

    service = contract.get("service_identity") or {}
    require(set(service.get("statuses") or []) == {"active", "suspended", "revoked"}, "service status set drifted")
    require(service.get("issuer_capability") == "issue_execution_authorization", "issuer capability drifted")
    require(service.get("executor_capability") == "execute_protection_action", "executor capability drifted")
    for key in (
        "active_identity_required_for_signing",
        "active_identity_required_for_execution_verification",
        "suspended_identity_fails_closed",
        "revoked_identity_fails_closed",
        "capability_binding_required",
    ):
        require(service.get(key) is True, f"missing service identity invariant: {key}")

    lifecycle = contract.get("signing_key_lifecycle") or {}
    require(set(lifecycle.get("statuses") or []) == {"active", "retired", "revoked"}, "key status set drifted")
    require(lifecycle.get("authorization_envelope_key_binding") == "signing_key_id", "authorization key binding drifted")
    for key in (
        "key_id_is_signed_material",
        "active_key_may_sign",
        "retired_key_may_verify_during_bounded_overlap",
        "revocation_takes_precedence_over_overlap",
        "unknown_key_fails_closed",
        "issuer_key_mismatch_fails_closed",
        "algorithm_mismatch_fails_closed",
    ):
        require(lifecycle.get(key) is True, f"missing key lifecycle invariant: {key}")
    for key in (
        "key_material_is_metadata",
        "key_material_allowed_in_authorization_envelope",
        "key_material_allowed_in_durable_execution_state",
        "key_material_allowed_in_shared_security_records",
        "key_material_allowed_in_application_source",
        "retired_key_may_sign",
        "revoked_key_may_verify",
    ):
        require(lifecycle.get(key) is False, f"unsafe key lifecycle invariant: {key}")
    require(lifecycle.get("maximum_reference_rotation_overlap_seconds") == 86400, "rotation overlap maximum drifted")

    crypto = contract.get("reference_cryptography") or {}
    require(crypto.get("algorithm") == "HMAC-SHA256-reference-only", "reference algorithm label drifted")
    require(crypto.get("reference_keyring_is_production_key_management") is False, "reference keyring must not imply production KMS")

    cloudflare = contract.get("cloudflare_candidate") or {}
    require(cloudflare.get("binding_scope_required") == "workers", "Cloudflare secret scope must be workers")
    require(cloudflare.get("secret_value_in_wrangler_configuration_allowed") is False, "Wrangler config must not contain secret values")
    require(cloudflare.get("secret_value_in_git_allowed") is False, "Git must not contain secret values")
    require(cloudflare.get("secret_value_in_ci_logs_allowed") is False, "CI logs must not contain secret values")
    require(cloudflare.get("deployment_time_provider_capability_and_permission_verification_required") is True, "provider capability verification must be required")

    authority = contract.get("authority_boundaries") or {}
    require(authority.get("service_identity_grants_target_resource_authority") is False, "identity must not grant target authority")
    require(authority.get("signing_key_grants_target_resource_authority") is False, "key must not grant target authority")
    require(authority.get("persistence_grants_executor_authority") is False, "persistence must not grant executor authority")
    require(authority.get("goreecloud_mesh_transport_grants_execution_authority") is False, "Mesh transport must not grant execution authority")
    require(authority.get("wardveil_policy_and_target_executor_authority_remain_distinct") is True, "Policy/executor authority separation required")

    production = contract.get("production_acceptance") or {}
    require(production.get("status") == "unaccepted", "source milestone must remain production-unaccepted")
    required = set(production.get("required_evidence") or [])
    for item in (
        "approved_production_signature_algorithm_and_key_management",
        "production_service_identity_issuance_and_authentication",
        "deployed_secret_or_key_binding_without_source_exposure",
        "rotation_overlap_runtime_test",
        "immediate_revocation_runtime_test",
        "authenticated_authorization_transport",
        "authorized_high_impact_executor_integration",
        "key_recovery_and_emergency_revocation_procedure",
    ):
        require(item in required, f"missing production evidence requirement: {item}")

    leaked = sorted(set(walk_keys(contract)) & FORBIDDEN_KEYS)
    require(not leaked, f"contract contains secret-bearing field names: {', '.join(leaked)}")

    for token in (
        "ISSUER_CAPABILITY = \"issue_execution_authorization\"",
        "EXECUTOR_CAPABILITY = \"execute_protection_action\"",
        "KEY_STATUSES = {\"active\", \"retired\", \"revoked\"}",
        "MAX_ROTATION_OVERLAP = timedelta(hours=24)",
        "signing_key_retired_for_signing",
        "signing_key_revoked",
        "service_identity_suspended",
        "service_identity_revoked",
        "create_identity_bound_execution_authorization",
        "verify_identity_bound_execution_authorization",
    ):
        require(token in reference, f"reference implementation missing invariant: {token}")

    for token in (
        "signing_key_id: str",
        '"signing_key_id": self.signing_key_id',
        '"signing_key_id": signing_key_id',
        "_canonical_identifier(signing_key_id, MAX_SIGNING_KEY_ID_LENGTH)",
        "_canonical_identifier(authorization.signing_key_id, MAX_SIGNING_KEY_ID_LENGTH)",
    ):
        require(token in runtime_reference, f"runtime authorization missing key binding: {token}")
    require(
        '"signing_key_id": signing_key_id.strip()' not in runtime_reference,
        "runtime authorization must not normalize signing key identifiers",
    )

    required_bindings = set(runtime_contract.get("required_bindings") or [])
    require("signing_key_id" in required_bindings, "runtime contract must require signing_key_id")
    runtime_invariants = runtime_contract.get("security_invariants") or {}
    require(runtime_invariants.get("exact_signing_key_id_binding_required") is True, "runtime contract must require exact key ID binding")

    identity_meta = identity.get("service_identity_contract") or {}
    require(identity_meta.get("contract_version") == "0.1.0", "identity metadata missing service identity contract")
    require(identity_meta.get("production_runtime_status") == "unaccepted", "identity metadata must preserve unaccepted status")

    for phrase in (
        "who is this service?",
        "every foundation 0.9 execution authorization now carries `signing_key_id`",
        "revocation is stronger than retirement",
        "cloudflare secrets store",
        "goreecloud mesh may carry authenticated authorization messages",
        "recovery must never silently restore a revoked key",
        "passing source ci",
    ):
        require(phrase in docs, f"documentation missing required boundary: {phrase}")

    print("Wardveil Foundation 0.9 service identity and key lifecycle validation passed.")


if __name__ == "__main__":
    main()
