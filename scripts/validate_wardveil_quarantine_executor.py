#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "wardveil.quarantine-executor.json"
DOC = ROOT / "docs/QUARANTINE-EXECUTOR.md"
REFERENCE = ROOT / "reference" / "wardveil_quarantine_executor.py"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> None:
    require(CONTRACT.is_file(), "missing quarantine executor contract")
    require(DOC.is_file(), "missing quarantine executor documentation")
    require(REFERENCE.is_file(), "missing quarantine executor reference")
    contract = json.loads(CONTRACT.read_text())
    doc = DOC.read_text()
    source = REFERENCE.read_text()

    require(contract.get("contract_version") == "0.1.0", "unexpected quarantine executor contract version")
    require(contract.get("foundation_version") == "0.9.0", "quarantine executor must target Foundation 0.9")
    require(contract.get("action") == "quarantine", "executor action must remain quarantine-only")
    require(contract.get("executor_identity") == "wardveil-quarantine-executor-runtime", "unexpected executor identity")
    require(contract.get("production_runtime_status") == "unaccepted", "source quarantine executor must remain production-unaccepted")

    authorization = contract.get("authorization") or {}
    for key in (
        "signed_execution_authorization_required",
        "service_identity_required",
        "active_executor_identity_required",
        "revoked_key_fails_closed",
        "suspended_or_revoked_executor_fails_closed",
        "exact_policy_digest_binding_required",
        "exact_action_scope_executor_and_correlation_binding_required",
        "authenticated_internal_transport_required",
    ):
        require(authorization.get(key) is True, f"missing fail-closed authorization requirement: {key}")
    require(authorization.get("maximum_authorization_ttl_seconds") == 300, "authorization TTL must remain five minutes")
    require(authorization.get("generic_public_execution_api_allowed") is False, "public execution API must remain prohibited")

    durable = contract.get("durable_execution") or {}
    require(durable.get("pre_execution_claim_required") is True, "durable pre-execution claim required")
    require(durable.get("claim_precedes_target_side_effect") is True, "claim must precede side effect")
    require(durable.get("blind_reexecution_after_uncertain_outcome_allowed") is False, "blind reexecution must remain prohibited")
    require(durable.get("pending_claim_retry_disposition") == "execution_reconciliation_required", "uncertain claim must reconcile")

    target = contract.get("target_adapter") or {}
    require(target.get("target_side_idempotency_required") is True, "target idempotency required")
    require(target.get("exact_quarantine_state_readback_required_for_success") is True, "target readback required")
    require(target.get("successful_apply_without_state_readback_is_sufficient") is False, "apply alone must not count as success")
    require(target.get("ambiguous_or_timeout_outcome") == "execution_reconciliation_required", "ambiguous target outcome must reconcile")
    require(target.get("deployment_target_is_source_placeholder") is True, "source target must remain a placeholder")

    expected_types = {"mail_attachment", "drive_file", "browser_download", "ai_artifact"}
    require(set(contract.get("initial_resource_types") or ()) == expected_types, "unexpected initial quarantine resource types")

    semantics = contract.get("quarantine_semantics") or {}
    require(semantics.get("quarantine_is_deletion") is False, "quarantine must not become deletion")
    require(semantics.get("new_quarantine_review_state") == "pending", "new quarantine must start pending")
    require(semantics.get("release_requires_separate_explicit_authority") is True, "release authority must remain separate")
    require(semantics.get("removal_requires_separate_explicit_destructive_authority") is True, "removal authority must remain separate")

    audit = contract.get("audit_and_security_center") or {}
    required_provenance = {"authorization_id", "issuer_id", "executor_id", "signing_key_id", "signature_algorithm"}
    require(set(audit.get("authorization_provenance_fields") or ()) == required_provenance, "audit provenance field set drift")
    require(audit.get("signing_key_material_allowed") is False, "signing key material must not enter audit")
    require(audit.get("credentials_or_tokens_allowed") is False, "credentials/tokens must not enter audit")
    require(audit.get("provenance_alone_creates_protected_state") is False, "provenance must not create protected state")

    privacy = contract.get("privacy") or {}
    for forbidden in ("raw_resource_content_required", "user_facing_filename_required", "raw_url_required", "credentials_allowed", "tokens_allowed", "signing_key_material_allowed"):
        require(privacy.get(forbidden) is False, f"privacy boundary drift: {forbidden}")

    cloudflare = contract.get("cloudflare_source_candidate") or {}
    require(cloudflare.get("target_service_binding_value") == "REPLACE_AT_DEPLOYMENT", "target binding must remain explicit source placeholder")
    require(cloudflare.get("production_signature_algorithm_accepted") is False, "reference HMAC must not become production accepted")
    require(cloudflare.get("public_fetch_behavior") == "404", "Cloudflare executor must remain non-public")

    for phrase in (
        "Quarantine is not deletion",
        "Production runtime status remains `unaccepted`",
        "REPLACE_AT_DEPLOYMENT",
        "target-state readback",
        "Privacy Shield remains",
        "Everkeep remains",
    ):
        require(phrase in doc, f"missing quarantine executor documentation invariant: {phrase}")

    for token in (
        "verify_identity_bound_execution_authorization",
        "state_store.claim",
        "target.apply_quarantine",
        "target.read_quarantine",
        "state_store.finalize",
        "authorization_provenance",
        "quarantine(",
    ):
        require(token in source, f"missing reference executor invariant: {token}")

    print("Wardveil quarantine executor contract validation passed")


if __name__ == "__main__":
    main()
