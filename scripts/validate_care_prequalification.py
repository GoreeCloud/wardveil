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
    for key in (
        "care_ci_run_id",
        "care_ci_run_number",
        "care_test_count",
        "platform_contract_run_id",
        "theme_validation_run_number",
        "primary_artifact_id",
        "cross_environment_artifact_id",
    ):
        require(positive_int(automated.get(key)), f"missing positive integer evidence: {key}")

    require(automated.get("care_ci_run_id") == 34180765807, "unexpected Care CI run")
    require(automated.get("care_ci_run_number") == 421, "unexpected Care CI run number")
    require(automated.get("care_test_count", 0) >= 143, "143-test qualification checkpoint missing")
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

    governance = record.get("governance") or {}
    require(governance.get("source_integration_status") == "implemented", "source integration must remain implemented")
    require(governance.get("representative_target_status") == "pending", "physical target must remain pending")
    require(governance.get("runtime_acceptance_status") == "unaccepted", "Wardveil runtime acceptance must remain unaccepted")
    for key in (
        "wardveil_adoption_promoted",
        "protected_by_wardveil_claim_allowed",
        "protected_by_wardveil",
        "cross_service_execution_authority_claimed",
        "privacy_shield_exact_candidate_runtime_accepted",
        "privacy_shield_production_approved",
        "stable_promotion_authorized",
    ):
        require(governance.get(key) is False, f"unsafe prequalification claim must remain false: {key}")

    requirements = record.get("remaining_requirements") or []
    require(isinstance(requirements, list) and len(requirements) >= 5, "remaining exact-candidate requirements must stay explicit")
    joined = "\n".join(str(item).lower() for item in requirements)
    for token in ("zorin os 17.3", "policykit", "privacy shield", "wardveil adoption", "protected by wardveil"):
        require(token in joined, f"missing remaining requirement: {token}")

    predecessor = record.get("predecessor_authority") or {}
    require(predecessor.get("wardveil_revision") == EXPECTED_PREDECESSOR_WARDVEIL, "unexpected predecessor Wardveil authority")
    require(predecessor.get("care_revision") == EXPECTED_PREDECESSOR_CARE, "unexpected predecessor Care authority")
    require(predecessor.get("historical_only") is True, "predecessor authority must be historical only")

    print("Care Wardveil exact-candidate prequalification: passed")
    print("Representative target: pending")
    print("Wardveil runtime acceptance: unaccepted")
    print("Wardveil adoption promoted: false")
    print("Protected by Wardveil claim allowed: false")


if __name__ == "__main__":
    main()
