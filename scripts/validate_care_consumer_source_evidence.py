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
    require(evidence.get("consumer_version") == "0.1.0-dev22", "unexpected Development version")
    require(evidence.get("consumer_package_version") == "0.1.0~dev22", "unexpected package version")
    require(evidence.get("representative_target") == "Zorin OS 17.3", "unexpected representative target")
    require(immutable_sha(evidence.get("consumer_revision")), "consumer revision must be immutable")
    require(immutable_sha(evidence.get("consumer_source_tree_sha")), "consumer source tree must be immutable")
    require(evidence.get("source_integration_status") == "implemented", "Care source integration must be explicitly implemented")
    require(evidence.get("runtime_acceptance_status") == "unaccepted", "current target evidence must remain unaccepted")
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
    require(details.get("consumer_ci_test_count", 0) >= 131, "Care evidence must preserve the 131-test checkpoint")
    require(sha256(details.get("consumer_package_sha256")), "CI package SHA-256 must be explicit")
    require(positive_int(details.get("consumer_ci_artifact_id")), "missing CI artifact ID")
    require(sha256(details.get("consumer_ci_artifact_digest")), "artifact digest must be SHA-256")

    # A source-only script/test change may legitimately not trigger the dedicated
    # Platform Contract workflow. Record that absence explicitly rather than
    # attaching an older workflow run to the current exact source revision.
    platform_triggered = details.get("consumer_platform_contract_workflow_triggered")
    require(platform_triggered is False, "current script/test-only Care update must record Platform Contract as not triggered")
    require(details.get("consumer_platform_contract_run_id") is None, "untriggered current Platform Contract must not invent a run ID")
    require(positive_int(details.get("consumer_last_successful_platform_contract_run_id")), "missing historical successful Platform Contract run ID")
    last_platform_revision = details.get("consumer_last_successful_platform_contract_revision")
    require(immutable_sha(last_platform_revision), "historical Platform Contract revision must be immutable")
    require(last_platform_revision != evidence.get("consumer_revision"), "historical Platform Contract run must not be relabeled as current exact-head evidence")

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
        "latest_representative_negative_evidence_exists",
        "historical_representative_zorin_lifecycle_evidence_exists",
        "historical_representative_zorin_exact_candidate_installed_boundary_acceptance_passed",
        "historical_representative_zorin_package_lifecycle_passed",
    ):
        require(details.get(key) is True, f"missing required Care evidence: {key}")

    for key in (
        "protected_by_wardveil_claim_allowed",
        "cross_service_execution_authority_claimed",
        "care_cleanup_invoked_by_lifecycle_prequalification",
        "current_representative_zorin_exact_candidate_installed_boundary_acceptance_passed",
        "historical_representative_zorin_cleanup_action_invoked",
        "historical_representative_zorin_reproducible_build_byte_identity_established",
    ):
        require(details.get(key) is False, f"unsafe, stale, or overbroad Care claim: {key}")

    require(details.get("current_representative_zorin_exact_candidate_revision") is None, "current source must not claim target acceptance before the fresh Zorin run")

    negative_revision = details.get("latest_representative_negative_evidence_revision")
    require(immutable_sha(negative_revision), "latest negative-evidence revision must be immutable")
    require(negative_revision != evidence.get("consumer_revision"), "stopped prior target attempt must not be relabeled as current acceptance")
    require(sha256(details.get("latest_representative_negative_evidence_package_sha256")), "negative-evidence package SHA-256 must be explicit")
    require(details.get("latest_representative_negative_evidence_test_count", 0) >= 130, "negative evidence must preserve the 130-test checkpoint")
    require(details.get("latest_representative_negative_evidence_stage") == "lifecycle-step-1-install-upgrade", "unexpected negative-evidence stage")
    negative_reason = str(details.get("latest_representative_negative_evidence_reason") or "").lower()
    require("did not replace" in negative_reason and "target handoff" in negative_reason, "negative evidence must retain the exact-package failure boundary")

    historical_lifecycle_revision = details.get("historical_representative_zorin_lifecycle_revision")
    historical_target_revision = details.get("historical_representative_zorin_exact_candidate_revision")
    require(immutable_sha(historical_lifecycle_revision), "historical lifecycle revision must be immutable")
    require(immutable_sha(historical_target_revision), "historical exact-target revision must be immutable")
    require(historical_target_revision != evidence.get("consumer_revision"), "historical target acceptance must not be carried forward")
    require(details.get("historical_representative_zorin_exact_candidate_test_count", 0) >= 106, "historical target must preserve 106-test checkpoint")
    require(sha256(details.get("historical_representative_zorin_final_lifecycle_package_sha256")), "historical final package SHA-256 must be explicit")
    require(sha256(details.get("historical_representative_zorin_pre_lifecycle_build_sha256")), "historical pre-lifecycle package SHA-256 must be explicit")
    require(details.get("historical_representative_zorin_final_lifecycle_package_sha256") != details.get("historical_representative_zorin_pre_lifecycle_build_sha256"), "historical non-byte-identical local rebuild evidence must remain explicit")

    remaining = set(evidence.get("runtime_acceptance_requirements_remaining") or [])
    required_remaining = {
        "representative_zorin_exact_candidate_installed_boundary_acceptance",
        "representative_zorin_policykit_agent_security_boundary_acceptance_if_required",
        "privacy_shield_exact_candidate_acceptance",
        "governed_wardveil_adoption_promotion",
        "immutable_release_candidate_regression_evidence",
    }
    require(required_remaining.issubset(remaining), "runtime acceptance remainder is incomplete")

    print("Wardveil GoreeCloud Care current-source evidence validation passed; current target acceptance remains unaccepted and historical/negative target evidence remains revision-scoped.")


if __name__ == "__main__":
    main()
