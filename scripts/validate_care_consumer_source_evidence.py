#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "contracts" / "wardveil.care.consumer-source-evidence.json"


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
        "consumer_revision": "334b53102c5fe0bd5d348397ba8b13cc5608ada2",
        "consumer_source_tree_sha": "4d8c243adb456913687045e67df509fb66736c28",
        "consumer_version": "0.1.0-dev22",
        "consumer_package_version": "0.1.0~dev22",
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

    require(details.get("consumer_ci_revision") == record["consumer_revision"], "CI revision mismatch")
    require(details.get("consumer_ci_source_tree_sha") == record["consumer_source_tree_sha"], "CI tree mismatch")
    require(details.get("consumer_ci_run_number") == 416, "unexpected Care RC run number")
    require(details.get("consumer_ci_run_id") == 34169330536, "unexpected Care RC run ID")
    require(details.get("consumer_platform_contract_run_id") == 34169330837, "unexpected Platform Contract run")
    require(details.get("consumer_theme_validation_run_id") == 34169330531, "unexpected theme validation run")
    require(details.get("consumer_ci_test_count", 0) >= 144, "144-test RC checkpoint missing")
    require(positive_int(details.get("consumer_ci_artifact_id")), "missing package artifact")
    require(positive_int(details.get("consumer_cross_environment_artifact_id")), "missing cross-environment artifact")
    require(sha256(details.get("consumer_ci_artifact_digest")), "invalid package artifact digest")
    require(sha256(details.get("consumer_cross_environment_artifact_digest")), "invalid cross-environment artifact digest")
    package_sha = details.get("consumer_package_sha256")
    require(sha256(package_sha), "invalid Care package SHA-256")
    require(details.get("consumer_cross_environment_ubuntu_22_04_sha256") == package_sha, "Ubuntu 22.04 package mismatch")
    require(details.get("consumer_cross_environment_ubuntu_24_04_sha256") == package_sha, "Ubuntu 24.04 package mismatch")

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
        "latest_representative_negative_evidence_exists",
        "prior_representative_negative_evidence_exists",
        "historical_representative_zorin_lifecycle_evidence_exists",
        "historical_representative_zorin_exact_candidate_installed_boundary_acceptance_passed",
        "historical_representative_zorin_package_lifecycle_passed",
    )
    for key in required_true:
        require(details.get(key) is True, f"missing required accepted evidence: {key}")

    require(details.get("protected_by_wardveil_claim_allowed") is True, "scoped Wardveil protection claim permission must be explicit")
    require(
        details.get("protected_by_wardveil_claim_scope") == "GoreeCloud Care local-maintenance-privilege-boundary only",
        "Wardveil protection permission must stay narrowly scoped",
    )
    require(details.get("cross_service_execution_authority_claimed") is False, "Care must not receive cross-service execution authority")
    require(details.get("care_cleanup_invoked_by_lifecycle_prequalification") is False, "Care cleanup must not be invoked by lifecycle prequalification")
    require(details.get("current_representative_zorin_cleanup_action_invoked") is False, "Care cleanup must not be invoked by representative lifecycle acceptance")
    require(details.get("representative_zorin_policykit_invalid_action_exit_status") == 64, "invalid helper action must fail closed with status 64")
    basis = str(details.get("representative_zorin_policykit_observation_basis") or "").lower()
    require("user-observed" in basis and "zorin os 17.3" in basis and "policykit" in basis, "PolicyKit physical acceptance basis must remain explicit")

    require(details.get("current_representative_zorin_exact_candidate_revision") == record["consumer_revision"], "target revision mismatch")
    require(details.get("current_representative_zorin_exact_candidate_source_tree_sha") == record["consumer_source_tree_sha"], "target tree mismatch")
    require(details.get("current_representative_zorin_exact_candidate_package_sha256") == package_sha, "target package mismatch")
    require(details.get("current_representative_zorin_exact_candidate_test_count", 0) >= 144, "target test checkpoint missing")
    require(details.get("current_representative_zorin_post_install_provenance_directory_mode") == "0755", "unexpected target provenance directory mode")
    require(details.get("current_representative_zorin_post_install_provenance_file_mode") == "0644", "unexpected target provenance file mode")

    require(
        details.get("privacy_shield_current_exact_candidate_acceptance_revision")
        == "d2ee2c626beb2ebc2d951d01db877fc8f46d3791",
        "unexpected current Privacy Shield authority",
    )

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
        "Wardveil GoreeCloud Care evidence validation passed; exact RC CI/package/physical target, "
        "Privacy Shield, real-desktop PolicyKit security-boundary evidence, and governed Wardveil "
        "adoption are accepted. Scoped Wardveil protection-claim permission is recorded without "
        "granting cross-service execution authority."
    )


if __name__ == "__main__":
    main()
