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
    require(
        evidence.get("consumer_repository") == "GoreeCloud/goreecloud-zorin-os",
        "unexpected consumer repository",
    )
    require(
        evidence.get("consumer_component") == "apps/goreecloud-care",
        "unexpected consumer component",
    )
    require(evidence.get("consumer_version") == "0.1.0-dev22", "unexpected Development version")
    require(evidence.get("consumer_package_version") == "0.1.0~dev22", "unexpected package version")
    require(evidence.get("representative_target") == "Zorin OS 17.3", "unexpected representative target")
    require(immutable_sha(evidence.get("consumer_revision")), "consumer revision must be immutable")
    require(immutable_sha(evidence.get("consumer_source_tree_sha")), "consumer source tree must be immutable")
    require(
        evidence.get("source_integration_status") == "implemented",
        "Care source integration must be explicitly implemented",
    )
    require(
        evidence.get("runtime_acceptance_status") == "unaccepted",
        "source evidence must not claim governed runtime acceptance",
    )
    require(
        evidence.get("source_evidence_is_production_protection_claim") is False,
        "source evidence must not authorize a production protection claim",
    )

    details = evidence.get("evidence") or {}
    for key, expected in {
        "consumer_integration_document": "apps/goreecloud-care/WARDVEIL-INTEGRATION.md",
        "consumer_platform_status_source": "apps/goreecloud-care/goreecloud_care/platform_status.py",
        "consumer_status_tests": "apps/goreecloud-care/tests/test_platform_status.py",
        "consumer_installed_acceptance": "apps/goreecloud-care/scripts/validate-installed.sh",
        "consumer_package_lifecycle_acceptance": "apps/goreecloud-care/scripts/validate-package-lifecycle.sh",
        "consumer_ci_workflow": ".github/workflows/care-ci.yml",
    }.items():
        require(details.get(key) == expected, f"unexpected consumer evidence path: {key}")

    require(immutable_sha(details.get("consumer_ci_revision")), "CI revision must be immutable")
    require(immutable_sha(details.get("consumer_ci_source_tree_sha")), "CI source tree must be immutable")
    require(
        details.get("consumer_ci_revision") == evidence.get("consumer_revision"),
        "consumer revision must equal tested CI revision",
    )
    require(
        details.get("consumer_ci_source_tree_sha") == evidence.get("consumer_source_tree_sha"),
        "consumer source tree must equal tested CI tree",
    )
    require(positive_int(details.get("consumer_ci_run_number")), "missing CI run number")
    require(positive_int(details.get("consumer_ci_run_id")), "missing CI run ID")
    require(positive_int(details.get("consumer_platform_contract_run_id")), "missing Platform Contract run ID")
    require(positive_int(details.get("consumer_theme_validation_run_id")), "missing theme validation run ID")
    require(details.get("consumer_ci_test_count", 0) >= 106, "Care evidence must preserve the 106-test checkpoint")
    require(sha256(details.get("consumer_package_sha256")), "package SHA-256 must be explicit")
    require(positive_int(details.get("consumer_ci_artifact_id")), "missing CI artifact ID")
    require(sha256(details.get("consumer_ci_artifact_digest")), "artifact digest must be SHA-256")
    require(immutable_sha(details.get("historical_representative_zorin_lifecycle_revision")), "historical target revision must be immutable")

    for key in (
        "exact_ci_revision_passed",
        "source_tree_matches_ci_tree",
        "installed_package_lifecycle_prequalification_passed",
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
        "historical_representative_zorin_lifecycle_evidence_exists",
    ):
        require(details.get(key) is True, f"missing required Care source evidence: {key}")

    for key in (
        "protected_by_wardveil_claim_allowed",
        "cross_service_execution_authority_claimed",
        "care_cleanup_invoked_by_lifecycle_prequalification",
    ):
        require(details.get(key) is False, f"unsafe or overbroad Care claim: {key}")

    remaining = set(evidence.get("runtime_acceptance_requirements_remaining") or [])
    required_remaining = {
        "representative_zorin_exact_candidate_installed_boundary_acceptance",
        "representative_zorin_policykit_agent_security_boundary_acceptance_if_required",
        "privacy_shield_exact_candidate_acceptance",
        "governed_wardveil_adoption_promotion",
        "immutable_release_candidate_regression_evidence",
    }
    require(required_remaining.issubset(remaining), "runtime acceptance remainder is incomplete")

    print("Wardveil GoreeCloud Care consumer source evidence validation passed.")


if __name__ == "__main__":
    main()
