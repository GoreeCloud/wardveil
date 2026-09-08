#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / "contracts" / "wardveil.care.prequalification.json"

EXPECTED_SOURCE = "bbc4779454c2887b810aa0ddc9e8a686a4c68ebd"
EXPECTED_TREE = "ebe028347c978b6d09fb1d2af011729249f63bc3"
EXPECTED_PACKAGE_SHA = "819cff6e0132bf6b09df0986682995c25b14c39e74982f725efd0b5a21b71160"
EXPECTED_PRIVACY = "0af47f4817191541e1ea12928cff5c3458baf377"
EXPECTED_PREDECESSOR_WARDVEIL = "e16fc489dbf98849601a198358863dffe7df81d4"
EXPECTED_PREDECESSOR_CARE = "334b53102c5fe0bd5d348397ba8b13cc5608ada2"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"Care Wardveil prequalification invalid: {message}")


def immutable_sha(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def main() -> None:
    require(RECORD.is_file(), "missing prequalification record")
    record = json.loads(RECORD.read_text(encoding="utf-8"))

    require(record.get("schema_version") == 1, "unexpected schema version")
    require(record.get("record_type") == "consumer-prequalification", "unexpected record type")
    require(record.get("consumer") == "GoreeCloud Care", "unexpected consumer")
    require(record.get("consumer_repository") == "GoreeCloud/goreecloud-zorin-os", "unexpected repository")
    require(record.get("consumer_component") == "apps/goreecloud-care", "unexpected component")

    candidate = record.get("candidate") or {}
    require(candidate.get("source_revision") == EXPECTED_SOURCE, "candidate source mismatch")
    require(candidate.get("source_tree_sha") == EXPECTED_TREE, "candidate tree mismatch")
    require(candidate.get("runtime_version") == "0.1.0", "unexpected runtime version")
    require(candidate.get("package_version") == "0.1.0", "unexpected package version")
    require(candidate.get("package_sha256") == EXPECTED_PACKAGE_SHA, "candidate package SHA mismatch")
    require(candidate.get("representative_target") == "Zorin OS 17.3", "unexpected representative target")
    require(immutable_sha(candidate.get("source_revision")), "source revision must be immutable")
    require(immutable_sha(candidate.get("source_tree_sha")), "source tree must be immutable")
    require(sha256(candidate.get("package_sha256")), "package SHA-256 must be explicit")

    automated = record.get("automated_prequalification") or {}
    require(automated.get("care_ci_run_id") == 34180765807, "unexpected Care CI run")
    require(automated.get("care_ci_run_number") == 421, "unexpected Care CI run number")
    require(automated.get("care_test_count") == 143, "143-test checkpoint missing")
    require(automated.get("platform_contract_run_id") == 34180766156, "unexpected Platform Contract run")
    require(automated.get("theme_validation_run_number") == 590, "unexpected theme run number")
    require(automated.get("primary_artifact_id") == 10038827656, "unexpected primary artifact")
    require(automated.get("cross_environment_artifact_id") == 10038821545, "unexpected cross-environment artifact")
    require(sha256(automated.get("primary_artifact_digest")), "invalid primary artifact digest")
    require(sha256(automated.get("cross_environment_artifact_digest")), "invalid cross-environment artifact digest")
    for key in (
        "exact_ci_revision_passed",
        "source_tree_matches_ci_tree",
        "same_environment_reproducibility_passed",
        "cross_umask_package_identity_passed",
        "cross_environment_package_identity_passed",
        "installed_package_lifecycle_prequalification_passed",
        "same_version_exact_package_reinstall_prequalification_passed",
        "installed_provenance_validation_passed",
        "installed_privilege_boundary_prequalification_passed",
        "working_directory_shadow_resistance_passed",
        "private_bytecode_cleanup_passed",
    ):
        require(automated.get(key) is True, f"automated qualification must remain passed: {key}")
    require(automated.get("care_cleanup_invoked_by_prequalification") is False, "prequalification must not invoke Care cleanup")

    physical = record.get("physical_target_evidence") or {}
    require(physical.get("status") == "passed", "physical target must be passed")
    require(physical.get("target") == "Zorin OS 17.3", "physical target mismatch")
    require(physical.get("source_revision") == EXPECTED_SOURCE, "physical source mismatch")
    require(physical.get("source_tree_sha") == EXPECTED_TREE, "physical tree mismatch")
    require(physical.get("package_sha256") == EXPECTED_PACKAGE_SHA, "physical package mismatch")
    require(physical.get("local_test_count") == 143, "physical 143-test checkpoint missing")
    for key in (
        "physical_package_matched_ci_sha256",
        "source_validation_passed",
        "same_environment_reproducibility_passed",
        "cross_umask_package_identity_passed",
        "package_lifecycle_passed",
        "candidate_install_upgrade_passed",
        "candidate_removal_passed",
        "fresh_reinstall_passed",
        "accepted_dev17_downgrade_passed",
        "candidate_restore_passed",
        "final_installed_state_passed",
        "representative_target_handoff_generated",
    ):
        require(physical.get(key) is True, f"missing physical acceptance evidence: {key}")
    require(physical.get("care_cleanup_invoked") is False, "physical acceptance must not invoke Care cleanup")
    require(physical.get("post_install_provenance_directory_mode") == "0755", "unexpected provenance directory mode")
    require(physical.get("post_install_provenance_file_mode") == "0644", "unexpected provenance file mode")
    require(physical.get("continuity_state_after_target_acceptance") == "attention", "Care must remain fail-closed before Everkeep governance")
    require(physical.get("continuity_stage_after_target_acceptance") == "target-accepted-governance-pending", "unexpected continuity stage")

    privacy = record.get("privacy_shield_authority") or {}
    require(privacy.get("runtime_accepted") is True, "Privacy Shield runtime acceptance missing")
    require(privacy.get("production_approved") is True, "Privacy Shield production approval missing")
    require(privacy.get("revision") == EXPECTED_PRIVACY, "unexpected Privacy Shield authority")
    require(privacy.get("validation_run_id") == 34183154605, "unexpected Privacy Shield validation run")
    require(privacy.get("validation_run_number") == 235, "unexpected Privacy Shield validation run number")
    require(set(privacy.get("scope") or []) == {"telemetry-minimization", "data-minimization", "privacy-status"}, "unexpected Privacy Shield scope")

    governance = record.get("governance") or {}
    require(governance.get("source_integration_status") == "implemented", "source integration must remain implemented")
    require(governance.get("representative_target_status") == "passed", "representative target must be passed")
    require(governance.get("runtime_acceptance_status") == "unaccepted", "Wardveil runtime acceptance must remain unaccepted until PolicyKit/adoption governance")
    require(governance.get("wardveil_adoption_promoted") is False, "Wardveil adoption must remain false")
    require(governance.get("protected_by_wardveil_claim_allowed") is False, "protection claim permission must remain false")
    require(governance.get("protected_by_wardveil") is False, "protection claim must remain false")
    require(governance.get("cross_service_execution_authority_claimed") is False, "cross-service execution authority must remain false")
    require(governance.get("privacy_shield_exact_candidate_runtime_accepted") is True, "current Privacy runtime gate must be passed")
    require(governance.get("privacy_shield_production_approved") is True, "current Privacy production gate must be passed")
    require(governance.get("stable_promotion_authorized") is False, "Stable promotion must remain unauthorized")

    requirements = record.get("remaining_requirements") or []
    require(isinstance(requirements, list) and len(requirements) == 3, "remaining Wardveil requirements must be exact")
    joined = "\n".join(str(item).lower() for item in requirements)
    for token in ("policykit", "wardveil adoption", "protected by wardveil"):
        require(token in joined, f"missing remaining requirement: {token}")
    require("physical zorin" not in joined, "passed physical target must not remain listed")
    require("privacy shield exact-candidate runtime acceptance" not in joined, "passed Privacy gate must not remain listed")

    predecessor = record.get("predecessor_authority") or {}
    require(predecessor.get("wardveil_revision") == EXPECTED_PREDECESSOR_WARDVEIL, "unexpected predecessor Wardveil authority")
    require(predecessor.get("care_revision") == EXPECTED_PREDECESSOR_CARE, "unexpected predecessor Care authority")
    require(predecessor.get("historical_only") is True, "predecessor authority must remain historical")

    print("Care Wardveil exact-candidate prequalification: passed")
    print("Representative target: passed")
    print("Privacy Shield exact-candidate approval: passed")
    print("Wardveil runtime acceptance: unaccepted")
    print("Wardveil adoption promoted: false")
    print("Protected by Wardveil claim allowed: false")


if __name__ == "__main__":
    main()
