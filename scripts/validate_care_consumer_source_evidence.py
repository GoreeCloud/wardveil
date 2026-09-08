#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "contracts" / "wardveil.care.consumer-source-evidence.json"

EXPECTED_SOURCE = "bbc4779454c2887b810aa0ddc9e8a686a4c68ebd"
EXPECTED_TREE = "ebe028347c978b6d09fb1d2af011729249f63bc3"
EXPECTED_PACKAGE_SHA = "819cff6e0132bf6b09df0986682995c25b14c39e74982f725efd0b5a21b71160"
EXPECTED_PRIVACY = "0af47f4817191541e1ea12928cff5c3458baf377"
EXPECTED_EVERKEEP = "4586246aad87a4038c7f8984de809d32333f2599"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"Wardveil Care consumer evidence validation failed: {message}")


def immutable_sha(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def main() -> None:
    require(EVIDENCE.is_file(), "missing Care consumer source evidence")
    record = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    details = record.get("evidence") or {}

    expected_identity = {
        "schema_version": 1,
        "consumer": "GoreeCloud Care",
        "consumer_repository": "GoreeCloud/goreecloud-zorin-os",
        "consumer_component": "apps/goreecloud-care",
        "consumer_revision": EXPECTED_SOURCE,
        "consumer_source_tree_sha": EXPECTED_TREE,
        "consumer_version": "0.1.0",
        "consumer_package_version": "0.1.0",
        "representative_target": "Zorin OS 17.3",
        "source_integration_status": "implemented",
        "runtime_acceptance_status": "accepted",
        "source_evidence_is_production_protection_claim": False,
    }
    for key, expected in expected_identity.items():
        require(record.get(key) == expected, f"unexpected {key}")

    require(immutable_sha(record["consumer_revision"]), "consumer revision must be immutable")
    require(immutable_sha(record["consumer_source_tree_sha"]), "consumer source tree must be immutable")

    expected_paths = {
        "consumer_integration_document": "apps/goreecloud-care/WARDVEIL-INTEGRATION.md",
        "consumer_platform_status_source": "apps/goreecloud-care/goreecloud_care/platform_status.py",
        "consumer_status_tests": "apps/goreecloud-care/tests/test_platform_status.py",
        "consumer_installed_acceptance": "apps/goreecloud-care/scripts/validate-installed.sh",
        "consumer_package_lifecycle_acceptance": "apps/goreecloud-care/scripts/validate-package-lifecycle.sh",
        "consumer_representative_acceptance": "apps/goreecloud-care/scripts/run-representative-acceptance.sh",
        "consumer_ci_workflow": ".github/workflows/care-ci.yml",
    }
    for key, expected in expected_paths.items():
        require(details.get(key) == expected, f"unexpected evidence path: {key}")

    require(details.get("consumer_ci_revision") == EXPECTED_SOURCE, "CI revision mismatch")
    require(details.get("consumer_ci_source_tree_sha") == EXPECTED_TREE, "CI tree mismatch")
    require(details.get("consumer_ci_run_number") == 421, "unexpected Care 0.1.0 run number")
    require(details.get("consumer_ci_run_id") == 34180765807, "unexpected Care 0.1.0 run ID")
    require(details.get("consumer_platform_contract_run_id") == 34180766156, "unexpected Platform Contract run")
    require(details.get("consumer_theme_validation_run_id") == 34180765817, "unexpected theme validation run")
    require(details.get("consumer_ci_test_count", 0) >= 143, "143-test exact-candidate checkpoint missing")
    require(details.get("consumer_package_sha256") == EXPECTED_PACKAGE_SHA, "unexpected Care package SHA-256")
    require(sha256(details.get("consumer_package_sha256")), "Care package SHA-256 must be explicit")
    require(details.get("consumer_ci_artifact_id") == 10038827656, "unexpected package artifact")
    require(details.get("consumer_cross_environment_artifact_id") == 10038821545, "unexpected cross-environment artifact")
    require(sha256(details.get("consumer_ci_artifact_digest")), "invalid package artifact digest")
    require(sha256(details.get("consumer_cross_environment_artifact_digest")), "invalid cross-environment artifact digest")
    require(details.get("consumer_cross_environment_ubuntu_22_04_sha256") == EXPECTED_PACKAGE_SHA, "Ubuntu 22.04 package mismatch")
    require(details.get("consumer_cross_environment_ubuntu_24_04_sha256") == EXPECTED_PACKAGE_SHA, "Ubuntu 24.04 package mismatch")

    required_true = (
        "exact_ci_revision_passed",
        "source_tree_matches_ci_tree",
        "installed_package_lifecycle_prequalification_passed",
        "same_version_exact_package_reinstall_prequalification_passed",
        "cross_umask_package_reproducibility_prequalification_passed",
        "installed_provenance_mode_repair_prequalification_passed",
        "installed_privilege_boundary_prequalification_passed",
        "root_owned_nonwritable_helper_required",
        "root_owned_nonwritable_policy_required",
        "pkexec_required",
        "working_directory_shadow_resistance_passed",
        "private_bytecode_cleanup_passed",
        "missing_or_writable_evidence_fails_closed",
        "passing_evidence_has_bounded_freshness",
        "explicit_text_state_semantics",
        "sensitive_evidence_minimized",
        "immutable_release_candidate_regression_evidence_passed",
        "current_representative_zorin_exact_candidate_installed_boundary_acceptance_passed",
        "current_representative_zorin_source_validation_passed",
        "current_representative_zorin_package_lifecycle_passed",
        "current_representative_zorin_same_version_exact_package_reinstall_passed",
        "current_representative_zorin_cross_umask_package_identity_passed",
        "current_representative_zorin_target_handoff_generated",
        "representative_zorin_policykit_agent_security_boundary_acceptance_passed",
        "representative_zorin_policykit_care_confirmation_cancellation_passed",
        "representative_zorin_policykit_authorization_cancellation_passed",
        "representative_zorin_policykit_apt_clean_success_passed",
        "representative_zorin_policykit_memory_reclaim_success_passed",
        "representative_zorin_policykit_invalid_action_rejected_passed",
        "representative_zorin_policykit_post_acceptance_installed_validation_passed",
        "representative_zorin_policykit_post_acceptance_security_status_passing",
        "representative_zorin_policykit_post_acceptance_continuity_ready",
        "governed_wardveil_adoption_promotion",
        "privacy_shield_current_exact_candidate_acceptance_passed",
        "privacy_shield_production_approved",
        "everkeep_current_exact_candidate_ready",
        "everkeep_current_exact_candidate_local_record_installed",
        "latest_representative_negative_evidence_exists",
        "prior_representative_negative_evidence_exists",
        "historical_representative_zorin_lifecycle_evidence_exists",
        "historical_representative_zorin_exact_candidate_installed_boundary_acceptance_passed",
        "historical_representative_zorin_package_lifecycle_passed",
    )
    for key in required_true:
        require(details.get(key) is True, f"missing required accepted evidence: {key}")

    require(details.get("protected_by_wardveil_claim_allowed") is True, "scoped Wardveil protection permission must be explicit")
    require(
        details.get("protected_by_wardveil_claim_scope") == "GoreeCloud Care local-maintenance-privilege-boundary only",
        "Wardveil protection permission must stay narrowly scoped",
    )
    require(details.get("cross_service_execution_authority_claimed") is False, "Care must not receive cross-service execution authority")
    require(details.get("care_cleanup_invoked_by_lifecycle_prequalification") is False, "Care cleanup must not be invoked by lifecycle prequalification")
    require(details.get("current_representative_zorin_cleanup_action_invoked") is False, "Care cleanup must not be invoked by target acceptance")

    require(details.get("current_representative_zorin_exact_candidate_revision") == EXPECTED_SOURCE, "target revision mismatch")
    require(details.get("current_representative_zorin_exact_candidate_source_tree_sha") == EXPECTED_TREE, "target tree mismatch")
    require(details.get("current_representative_zorin_exact_candidate_package_sha256") == EXPECTED_PACKAGE_SHA, "target package mismatch")
    require(details.get("current_representative_zorin_exact_candidate_test_count", 0) >= 143, "target test checkpoint missing")
    require(details.get("current_representative_zorin_post_install_provenance_directory_mode") == "0755", "unexpected target provenance directory mode")
    require(details.get("current_representative_zorin_post_install_provenance_file_mode") == "0644", "unexpected target provenance file mode")

    require(details.get("representative_zorin_policykit_invalid_action_exit_status") == 64, "invalid helper action must fail closed with status 64")
    basis = str(details.get("representative_zorin_policykit_observation_basis") or "").lower()
    for token in ("user-observed", "zorin os 17.3", "0.1.0", "policykit", "six"):
        require(token in basis, f"PolicyKit acceptance basis missing token: {token}")

    require(details.get("privacy_shield_current_exact_candidate_acceptance_revision") == EXPECTED_PRIVACY, "unexpected Privacy Shield authority")
    require(details.get("privacy_shield_current_exact_candidate_validation_run_id") == 34183154605, "unexpected Privacy Shield validation run")
    require(details.get("everkeep_current_exact_candidate_authority_revision") == EXPECTED_EVERKEEP, "unexpected Everkeep authority")
    require(details.get("everkeep_current_exact_candidate_local_trust_directory_mode") == "0755", "unexpected Everkeep trust directory mode")
    require(details.get("everkeep_current_exact_candidate_local_trust_file_mode") == "0644", "unexpected Everkeep trust file mode")
    require(details.get("everkeep_current_exact_candidate_continuity_state") == "ready", "Everkeep continuity must be ready")
    require(details.get("everkeep_current_exact_candidate_continuity_stage") == "everkeep-promoted", "Everkeep stage mismatch")

    require(details.get("latest_representative_negative_evidence_target_handoff_generated") is False, "failed 387ebe target must not acquire a handoff")
    require(details.get("historical_representative_zorin_cleanup_action_invoked") is False, "historical lifecycle must preserve no-cleanup boundary")
    require(details.get("historical_representative_zorin_reproducible_build_byte_identity_established") is False, "historical non-reproducibility must remain explicit")

    for key in (
        "latest_representative_negative_evidence_revision",
        "latest_representative_negative_evidence_source_tree_sha",
        "prior_representative_negative_evidence_revision",
        "historical_representative_zorin_lifecycle_revision",
        "historical_representative_zorin_exact_candidate_revision",
    ):
        require(immutable_sha(details.get(key)), f"invalid immutable historical revision: {key}")
    for key in (
        "latest_representative_negative_evidence_package_sha256",
        "latest_representative_negative_evidence_same_source_ci_package_sha256",
        "prior_representative_negative_evidence_package_sha256",
        "historical_representative_zorin_final_lifecycle_package_sha256",
        "historical_representative_zorin_pre_lifecycle_build_sha256",
    ):
        require(sha256(details.get(key)), f"invalid historical package SHA-256: {key}")

    require(record.get("runtime_acceptance_requirements_remaining") == [], "accepted Care Wardveil adoption must have no runtime acceptance remainder")

    print(
        "Wardveil GoreeCloud Care evidence validation passed for exact 0.1.0: CI/package/physical target, "
        "Privacy Shield, local Everkeep readiness, real-desktop PolicyKit security-boundary evidence, "
        "and governed Wardveil adoption are accepted. Protection-claim permission remains narrowly scoped "
        "to the Care local-maintenance-privilege-boundary with no cross-service execution authority."
    )


if __name__ == "__main__":
    main()
