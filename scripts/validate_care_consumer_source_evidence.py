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
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))

    require(evidence.get("schema_version") == 1, "unexpected evidence schema version")
    require(evidence.get("consumer") == "GoreeCloud Care", "unexpected consumer identity")
    require(evidence.get("consumer_repository") == "GoreeCloud/goreecloud-zorin-os", "unexpected consumer repository")
    require(evidence.get("consumer_component") == "apps/goreecloud-care", "unexpected consumer component")
    require(evidence.get("consumer_version") == "0.1.0-dev22", "unexpected Care runtime version")
    require(evidence.get("consumer_package_version") == "0.1.0~dev22", "unexpected package version")
    require(evidence.get("representative_target") == "Zorin OS 17.3", "unexpected representative target")
    require(immutable_sha(evidence.get("consumer_revision")), "consumer revision must be immutable")
    require(immutable_sha(evidence.get("consumer_source_tree_sha")), "consumer source tree must be immutable")
    require(evidence.get("source_integration_status") == "implemented", "Care source integration must be explicitly implemented")
    # Exact target/RC/Privacy evidence is not Wardveil adoption/protection promotion.
    require(evidence.get("runtime_acceptance_status") == "unaccepted", "governed Wardveil runtime adoption must remain unaccepted")
    require(evidence.get("source_evidence_is_production_protection_claim") is False, "source evidence must not authorize protection")

    details = evidence.get("evidence") or {}
    for key, expected in {
        "consumer_integration_document": "apps/goreecloud-care/WARDVEIL-INTEGRATION.md",
        "consumer_platform_status_source": "apps/goreecloud-care/goreecloud_care/platform_status.py",
        "consumer_status_tests": "apps/goreecloud-care/tests/test_platform_status.py",
        "consumer_installed_acceptance": "apps/goreecloud-care/scripts/validate-installed.sh",
        "consumer_package_lifecycle_acceptance": "apps/goreecloud-care/scripts/validate-package-lifecycle.sh",
        "consumer_representative_acceptance": "apps/goreecloud-care/scripts/run-representative-acceptance.sh",
        "consumer_ci_workflow": ".github/workflows/care-ci.yml",
    }.items():
        require(details.get(key) == expected, f"unexpected consumer evidence path: {key}")

    require(immutable_sha(details.get("consumer_ci_revision")), "CI revision must be immutable")
    require(immutable_sha(details.get("consumer_ci_source_tree_sha")), "CI source tree must be immutable")
    require(details.get("consumer_ci_revision") == evidence.get("consumer_revision"), "current consumer revision must equal tested CI revision")
    require(details.get("consumer_ci_source_tree_sha") == evidence.get("consumer_source_tree_sha"), "current consumer source tree must equal tested CI tree")
    require(positive_int(details.get("consumer_ci_run_number")), "missing CI run number")
    require(positive_int(details.get("consumer_ci_run_id")), "missing CI run ID")
    require(positive_int(details.get("consumer_theme_validation_run_id")), "missing theme validation run ID")
    require(details.get("consumer_ci_test_count", 0) >= 144, "Care RC evidence must preserve the 144-test checkpoint")
    require(sha256(details.get("consumer_package_sha256")), "CI package SHA-256 must be explicit")
    require(positive_int(details.get("consumer_ci_artifact_id")), "missing CI artifact ID")
    require(sha256(details.get("consumer_ci_artifact_digest")), "artifact digest must be SHA-256")

    require(details.get("consumer_platform_contract_workflow_triggered") is True, "current Care revision must record its triggered Platform Contract workflow")
    require(positive_int(details.get("consumer_platform_contract_run_id")), "missing current Platform Contract run ID")
    require(positive_int(details.get("consumer_last_successful_platform_contract_run_id")), "missing historical successful Platform Contract run ID")
    last_platform_revision = details.get("consumer_last_successful_platform_contract_revision")
    require(immutable_sha(last_platform_revision), "historical Platform Contract revision must be immutable")
    require(last_platform_revision != evidence.get("consumer_revision"), "historical Platform Contract revision must remain distinct from current exact-head evidence")

    require(details.get("consumer_cross_environment_reproducibility_passed") is True, "current Care package must have cross-environment reproducibility evidence")
    require(positive_int(details.get("consumer_cross_environment_artifact_id")), "missing cross-environment artifact ID")
    require(sha256(details.get("consumer_cross_environment_artifact_digest")), "cross-environment artifact digest must be SHA-256")
    ubuntu_22_sha = details.get("consumer_cross_environment_ubuntu_22_04_sha256")
    ubuntu_24_sha = details.get("consumer_cross_environment_ubuntu_24_04_sha256")
    require(sha256(ubuntu_22_sha), "Ubuntu 22.04 package SHA-256 must be explicit")
    require(sha256(ubuntu_24_sha), "Ubuntu 24.04 package SHA-256 must be explicit")
    require(ubuntu_22_sha == ubuntu_24_sha, "cross-environment package bytes must agree")
    require(ubuntu_22_sha == details.get("consumer_package_sha256"), "CI package SHA-256 must equal cross-environment package SHA-256")

    for key in (
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
        "privacy_shield_current_exact_candidate_acceptance_passed",
        "privacy_shield_production_approved",
        "latest_representative_negative_evidence_exists",
        "prior_representative_negative_evidence_exists",
        "historical_representative_zorin_lifecycle_evidence_exists",
        "historical_representative_zorin_exact_candidate_installed_boundary_acceptance_passed",
        "historical_representative_zorin_package_lifecycle_passed",
    ):
        require(details.get(key) is True, f"missing required Care evidence: {key}")

    for key in (
        "protected_by_wardveil_claim_allowed",
        "cross_service_execution_authority_claimed",
        "care_cleanup_invoked_by_lifecycle_prequalification",
        "current_representative_zorin_cleanup_action_invoked",
        "latest_representative_negative_evidence_target_handoff_generated",
        "historical_representative_zorin_cleanup_action_invoked",
        "historical_representative_zorin_reproducible_build_byte_identity_established",
    ):
        require(details.get(key) is False, f"unsafe, stale, or overbroad Care claim: {key}")

    # Current physical exact-target evidence must bind to the same source/tree/package as CI.
    current_target_revision = details.get("current_representative_zorin_exact_candidate_revision")
    current_target_tree = details.get("current_representative_zorin_exact_candidate_source_tree_sha")
    current_target_package = details.get("current_representative_zorin_exact_candidate_package_sha256")
    require(current_target_revision == evidence.get("consumer_revision"), "current target revision must equal current Care revision")
    require(current_target_tree == evidence.get("consumer_source_tree_sha"), "current target tree must equal current Care tree")
    require(current_target_package == details.get("consumer_package_sha256"), "current physical package must equal current CI/cross-environment package")
    require(details.get("current_representative_zorin_exact_candidate_test_count", 0) >= 144, "current target must preserve the 144-test checkpoint")
    require(details.get("current_representative_zorin_post_install_provenance_directory_mode") == "0755", "current target must preserve repaired provenance directory mode")
    require(details.get("current_representative_zorin_post_install_provenance_file_mode") == "0644", "current target must preserve repaired provenance file mode")

    privacy_revision = details.get("privacy_shield_current_exact_candidate_acceptance_revision")
    require(immutable_sha(privacy_revision), "current Privacy Shield acceptance revision must be immutable")

    # Latest negative physical evidence: 387ebe proved exact same-version package
    # replacement but exposed cross-host package-mode/provenance trust variance.
    negative_revision = details.get("latest_representative_negative_evidence_revision")
    require(immutable_sha(negative_revision), "latest negative-evidence revision must be immutable")
    require(negative_revision != evidence.get("consumer_revision"), "failed prior target attempt must not be relabeled as current acceptance")
    require(immutable_sha(details.get("latest_representative_negative_evidence_source_tree_sha")), "latest negative-evidence Care tree must be immutable")
    physical_sha = details.get("latest_representative_negative_evidence_package_sha256")
    same_source_ci_sha = details.get("latest_representative_negative_evidence_same_source_ci_package_sha256")
    require(sha256(physical_sha), "latest negative-evidence physical package SHA-256 must be explicit")
    require(sha256(same_source_ci_sha), "latest negative-evidence same-source CI package SHA-256 must be explicit")
    require(physical_sha != same_source_ci_sha, "latest negative evidence must preserve the observed same-source package mismatch")
    require(details.get("latest_representative_negative_evidence_test_count", 0) >= 131, "latest negative evidence must preserve the 131-test checkpoint")
    require(details.get("latest_representative_negative_evidence_same_version_reinstall_passed") is True, "latest negative evidence must preserve successful same-version exact reinstall")
    require(details.get("latest_representative_negative_evidence_stage") == "post-install-continuity-trust-validation-before-lifecycle-step-2", "unexpected latest negative-evidence stage")
    negative_reason = str(details.get("latest_representative_negative_evidence_reason") or "").lower()
    require("reinstalled" in negative_reason and "differed" in negative_reason and "no target handoff" in negative_reason, "latest negative evidence must retain the package/provenance failure boundary")

    # Prior negative physical evidence: 16cbd exposed APT same-version no-op.
    prior_negative_revision = details.get("prior_representative_negative_evidence_revision")
    require(immutable_sha(prior_negative_revision), "prior negative-evidence revision must be immutable")
    require(prior_negative_revision != evidence.get("consumer_revision"), "prior failed target attempt must remain historical")
    require(prior_negative_revision != negative_revision, "negative physical checkpoints must remain distinct")
    require(sha256(details.get("prior_representative_negative_evidence_package_sha256")), "prior negative-evidence package SHA-256 must be explicit")
    require(details.get("prior_representative_negative_evidence_test_count", 0) >= 130, "prior negative evidence must preserve the 130-test checkpoint")
    require(details.get("prior_representative_negative_evidence_stage") == "lifecycle-step-1-install-upgrade", "unexpected prior negative-evidence stage")
    prior_reason = str(details.get("prior_representative_negative_evidence_reason") or "").lower()
    require("did not replace" in prior_reason and "target handoff" in prior_reason, "prior negative evidence must retain the same-version replacement failure boundary")

    historical_lifecycle_revision = details.get("historical_representative_zorin_lifecycle_revision")
    historical_target_revision = details.get("historical_representative_zorin_exact_candidate_revision")
    require(immutable_sha(historical_lifecycle_revision), "historical lifecycle revision must be immutable")
    require(immutable_sha(historical_target_revision), "historical exact-target revision must be immutable")
    require(historical_target_revision != evidence.get("consumer_revision"), "historical target acceptance must remain revision-scoped")
    require(details.get("historical_representative_zorin_exact_candidate_test_count", 0) >= 106, "historical target must preserve 106-test checkpoint")
    require(sha256(details.get("historical_representative_zorin_final_lifecycle_package_sha256")), "historical final package SHA-256 must be explicit")
    require(sha256(details.get("historical_representative_zorin_pre_lifecycle_build_sha256")), "historical pre-lifecycle package SHA-256 must be explicit")
    require(details.get("historical_representative_zorin_final_lifecycle_package_sha256") != details.get("historical_representative_zorin_pre_lifecycle_build_sha256"), "historical non-byte-identical local rebuild evidence must remain explicit")

    remaining = set(evidence.get("runtime_acceptance_requirements_remaining") or [])
    required_remaining = {
        "representative_zorin_policykit_agent_security_boundary_acceptance_if_required",
        "governed_wardveil_adoption_promotion",
    }
    require(required_remaining.issubset(remaining), "runtime acceptance remainder is incomplete")
    require("representative_zorin_exact_candidate_installed_boundary_acceptance" not in remaining, "passed exact-target acceptance must not remain open")
    require("privacy_shield_exact_candidate_acceptance" not in remaining, "passed exact Privacy Shield acceptance must not remain open")
    require("immutable_release_candidate_regression_evidence" not in remaining, "passed immutable RC regression evidence must not remain open")

    print("Wardveil GoreeCloud Care evidence validation passed; exact current RC CI/package/target evidence and Care-specific Privacy Shield production approval are recorded, while governed Wardveil adoption/protection remains unaccepted.")


if __name__ == "__main__":
    main()
