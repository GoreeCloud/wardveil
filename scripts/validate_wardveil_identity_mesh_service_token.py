#!/usr/bin/env python3
"""Validate Wardveil's bounded GoreeCloud Identity Mesh credential contract."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "wardveil.identity-mesh-service-token-consumer.json"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> None:
    data = json.loads(CONTRACT.read_text(encoding="utf-8"))

    require(data.get("contract_type") == "goreecloud-identity-mesh-service-token-consumer", "wrong contract type")
    require(data.get("consumer") == "wardveil-security", "wrong consumer")
    require(data.get("identity_authority_repository") == "GoreeCloud/goreecloud-identity", "wrong Identity authority")
    require(data.get("identity_authority_profile") == "goreecloud-identity.mesh-service-token.v1", "wrong Identity token profile")
    require(data.get("identity_candidate_schema_version") == "1.3.0", "unexpected Identity candidate schema")

    use = data.get("credential_use") or {}
    require(use.get("issuer") == "goreecloud-identity", "issuer must be GoreeCloud Identity")
    require(use.get("audience") == "goreecloud-mesh", "Identity Mesh token must remain Mesh-audience scoped")
    require(use.get("subject") == "service:wardveil-security", "wrong Wardveil service subject")
    require(use.get("service_id") == "wardveil-security", "wrong Wardveil service_id")
    require(use.get("required_scope") == "mesh.evidence.write", "Wardveil delivery requires mesh.evidence.write only")
    require(use.get("default_lifetime_seconds") == 300, "unexpected default token lifetime")
    require(use.get("maximum_lifetime_seconds") == 900, "unexpected maximum token lifetime")
    require(use.get("clock_skew_seconds") == 60, "unexpected clock skew")

    signing = data.get("signing_profile") or {}
    require(signing.get("algorithm") == "RS256", "only RS256 is accepted by this candidate profile")
    require(signing.get("minimum_rsa_key_bits") == 2048, "minimum RSA strength mismatch")
    require(signing.get("kid_required") is True, "kid must be required")
    require(signing.get("verification_keys") == "JWKS", "verification keys must be JWKS")
    require(signing.get("jwks_media_type") == "application/json", "JWKS media type mismatch")
    require(signing.get("token_selected_or_embedded_key_sources_allowed") is False, "token-selected key sources must be forbidden")
    require(set(signing.get("rejected_key_source_headers") or []) == {"jku", "jwk", "x5u", "x5c"}, "rejected key-source header set mismatch")

    behavior = data.get("wardveil_behavior") or {}
    for key in (
        "wardveil_may_mint_identity_credentials",
        "wardveil_may_export_identity_private_keys",
        "wardveil_may_reinterpret_identity_credential_semantics",
        "wardveil_may_use_mesh_credential_as_direct_protection_authorization",
        "mesh_delivery_success_implies_protection_success",
        "mesh_delivery_success_implies_security_state",
        "credential_may_be_persisted_in_evidence",
        "credential_may_be_logged",
        "credential_may_be_returned_in_delivery_receipts",
    ):
        require(behavior.get(key) is False, f"{key} must remain false")

    trust = data.get("trust_boundary") or {}
    require(trust.get("identity_owns_service_identity_and_credential_issuance") is True, "Identity authority boundary missing")
    require(trust.get("mesh_owns_verification_for_mesh_audience") is True, "Mesh verifier boundary missing")
    require(trust.get("wardveil_owns_security_semantics") is True, "Wardveil security authority boundary missing")
    require(trust.get("wardveil_direct_execution_authorization_is_separate") is True, "direct execution authorization must remain separate")

    status = data.get("source_status") or {}
    require(status.get("wardveil_consumer_contract_implemented") is True, "source contract must identify implementation")
    require(status.get("identity_candidate_contract_is_draft") is True, "Identity candidate must remain marked draft")
    for key in (
        "identity_durable_private_key_storage_integrated",
        "identity_jwks_endpoint_deployed",
        "identity_live_service_issuance_deployed",
        "end_to_end_runtime_acceptance",
        "production_acceptance",
    ):
        require(status.get(key) is False, f"{key} must remain false until separately verified")

    serialized = CONTRACT.read_text(encoding="utf-8").lower()
    for forbidden in ("private_key\":", "access_token\":", "refresh_token\":", "password\":", "bearer ey"):
        require(forbidden not in serialized, f"forbidden credential-like material in contract: {forbidden}")

    print("Wardveil GoreeCloud Identity Mesh service-token consumer contract validated.")


if __name__ == "__main__":
    main()
