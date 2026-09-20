#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "contracts" / "wardveil.privacy-shield.consumer-source-evidence.json"
DOC = ROOT / "PRIVACY-SHIELD.md"

EXPECTED_REVISION = "35375db7596a8892ccb5b9b27fa7d3ad80353d66"
EXPECTED_TREE = "29cd3d6a21d1bcf5a8b3b7415a0147920ab02791"
EXPECTED_STATUS_SCHEMA_BLOB = "f6b62576e68e19ad8b25ced5383f8a3df74716fb"
EXPECTED_STATUS_VALIDATOR_BLOB = "22dd5fb95641a663f79822c66bc8f92422064741"
EXPECTED_PROVIDER_GATE_BLOB = "23a53b5d40865159fe748348a0a178cd668dc9ff"
EXPECTED_STATE_ACCEPTANCE_SCHEMA_BLOB = "b47891772ddec46e2bf522c6a6405423e426ec2a"
EXPECTED_SIGNING_ACCEPTANCE_SCHEMA_BLOB = "4954b0ba76f8d250b2683b98c42df96eb6edf05e"
EXPECTED_WORKFLOW_BLOB = "4f5fece3c321baf6733e9c2ca187bac4216bbe3a"
EXPECTED_STATE_CANDIDATE_BLOB = "c041fda55efd4a29f7d1bf0fc1c8d5ac2281a0ae"
EXPECTED_SIGNING_CANDIDATE_BLOB = "d3744c677f1c3111e5559c145e293931a236db5c"
EXPECTED_STATE_PACKAGE_BLOB = "0eae49b84d63b78338b380f6de1e77d05d10352f"
EXPECTED_SIGNING_PACKAGE_BLOB = "ccb916e142cc80d06328f8396dfc047fb218d040"
EXPECTED_VALIDATION_RUN = 35542388611
EXPECTED_VALIDATION_RUN_NUMBER = 503
EXPECTED_STATE_OPERATIONAL_PACKAGE_BLOB = "24c70733e0e0c3b2fe23e1f50323e239fb0b55c8"
EXPECTED_SIGNING_LIFECYCLE_PACKAGE_BLOB = "db95c334efca5344add9dd0f8d9d847d0866eae0"
EXPECTED_STATE_CAPABILITY_REVIEW_BLOB = "52f9296b3d4a2317eb03c9606327ad5eec58d433"
EXPECTED_STATE_OPERATIONAL_REVIEW_BLOB = "af183c19c77659e7599e5d50c217a1efb73edc07"
EXPECTED_SIGNING_CAPABILITY_REVIEW_BLOB = "6c2e5c6de05cf0ac3572eb805b476e45c3fe4b94"
EXPECTED_SIGNING_LIFECYCLE_REVIEW_BLOB = "ea68b26817adb3ac59e55b7687d3bcb249360d05"
EXPECTED_ACCESS_CONTROL_ASSESSMENT_SCHEMA_BLOB = "b1ddd9716a3a748b40ec9b7b665578f7bd068d59"
EXPECTED_ACCESS_CONTROL_ASSESSMENT_VALIDATOR_BLOB = "051dde00c2bc7edeb8f22872a107f876f59e517a"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"Wardveil Privacy Shield producer-source evidence validation failed: {message}")


def immutable_sha(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def main() -> None:
    require(EVIDENCE.is_file(), "missing producer-source evidence record")
    require(DOC.is_file(), "missing PRIVACY-SHIELD.md")
    record = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    details = record.get("evidence") or {}

    expected_identity = {
        "schema_version": 1,
        "producer": "GoreeCloud Privacy Shield",
        "producer_repository": "GoreeCloud/privacy-shield",
        "producer_revision": EXPECTED_REVISION,
        "producer_source_tree_sha": EXPECTED_TREE,
        "integration": "Wardveil read-only Privacy Shield status consumer",
        "source_integration_status": "implemented",
        "runtime_acceptance_status": "unaccepted",
        "provider_production_acceptance_status": "unaccepted",
        "source_evidence_is_runtime_acceptance": False,
        "source_evidence_is_production_acceptance": False,
        "source_evidence_authorizes_protected_by_wardveil": False,
    }
    for key, expected in expected_identity.items():
        require(record.get(key) == expected, f"unexpected {key}")

    require(immutable_sha(record["producer_revision"]), "producer revision must be immutable")
    require(immutable_sha(record["producer_source_tree_sha"]), "producer tree must be immutable")

    expected_paths = {
        "privacy_status_schema": "contracts/privacy-shield.status.schema.json",
        "privacy_status_validator": "src/privacy-status-record.mjs",
        "provider_acceptance_gate": "tools/validate_provider_acceptance_gate.py",
        "state_provider_acceptance_schema": "contracts/privacy-shield.state-provider-acceptance.schema.json",
        "signing_provider_acceptance_schema": "contracts/privacy-shield.signing-key-provider-acceptance.schema.json",
        "state_provider_candidate_evaluation": "evaluations/state-providers/foundationdb-self-hosted-multihost-production.json",
        "signing_provider_candidate_evaluation": "evaluations/signing-key-providers/ovhcloud-kms-hsm-production.json",
        "state_provider_candidate_evidence_package": "evidence/provider-evaluations/foundationdb-state-candidate-20260919.json",
        "signing_provider_candidate_evidence_package": "evidence/provider-evaluations/ovhcloud-kms-hsm-signing-candidate-20260919.json",
        "state_provider_operational_evidence_package": "evidence/provider-evaluations/foundationdb-operational-security-candidate-20260919.json",
        "signing_provider_lifecycle_evidence_package": "evidence/provider-evaluations/ovhcloud-kms-signing-lifecycle-audit-candidate-20260919.json",
        "state_provider_capability_review_attestation": "reviews/provider-evidence/foundationdb-state-candidate-docs-review-20260919.json",
        "state_provider_operational_review_attestation": "reviews/provider-evidence/foundationdb-operational-security-review-20260919.json",
        "signing_provider_capability_review_attestation": "reviews/provider-evidence/ovhcloud-kms-hsm-signing-docs-review-20260919.json",
        "signing_provider_lifecycle_review_attestation": "reviews/provider-evidence/ovhcloud-kms-signing-lifecycle-audit-review-20260919.json",
        "provider_access_control_assessment_schema": "contracts/privacy-shield.provider-access-control-assessment.schema.json",
        "provider_access_control_assessment_validator": "tools/validate_provider_access_control_assessments.py",
        "producer_validation_workflow": ".github/workflows/validate.yml",
    }
    for key, expected in expected_paths.items():
        require(details.get(key) == expected, f"unexpected producer path for {key}")

    expected_blobs = {
        "privacy_status_schema_git_blob_sha": EXPECTED_STATUS_SCHEMA_BLOB,
        "privacy_status_validator_git_blob_sha": EXPECTED_STATUS_VALIDATOR_BLOB,
        "provider_acceptance_gate_git_blob_sha": EXPECTED_PROVIDER_GATE_BLOB,
        "state_provider_acceptance_schema_git_blob_sha": EXPECTED_STATE_ACCEPTANCE_SCHEMA_BLOB,
        "signing_provider_acceptance_schema_git_blob_sha": EXPECTED_SIGNING_ACCEPTANCE_SCHEMA_BLOB,
        "state_provider_candidate_evaluation_git_blob_sha": EXPECTED_STATE_CANDIDATE_BLOB,
        "signing_provider_candidate_evaluation_git_blob_sha": EXPECTED_SIGNING_CANDIDATE_BLOB,
        "state_provider_candidate_evidence_package_git_blob_sha": EXPECTED_STATE_PACKAGE_BLOB,
        "signing_provider_candidate_evidence_package_git_blob_sha": EXPECTED_SIGNING_PACKAGE_BLOB,
        "state_provider_operational_evidence_package_git_blob_sha": EXPECTED_STATE_OPERATIONAL_PACKAGE_BLOB,
        "signing_provider_lifecycle_evidence_package_git_blob_sha": EXPECTED_SIGNING_LIFECYCLE_PACKAGE_BLOB,
        "state_provider_capability_review_attestation_git_blob_sha": EXPECTED_STATE_CAPABILITY_REVIEW_BLOB,
        "state_provider_operational_review_attestation_git_blob_sha": EXPECTED_STATE_OPERATIONAL_REVIEW_BLOB,
        "signing_provider_capability_review_attestation_git_blob_sha": EXPECTED_SIGNING_CAPABILITY_REVIEW_BLOB,
        "signing_provider_lifecycle_review_attestation_git_blob_sha": EXPECTED_SIGNING_LIFECYCLE_REVIEW_BLOB,
        "provider_access_control_assessment_schema_git_blob_sha": EXPECTED_ACCESS_CONTROL_ASSESSMENT_SCHEMA_BLOB,
        "provider_access_control_assessment_validator_git_blob_sha": EXPECTED_ACCESS_CONTROL_ASSESSMENT_VALIDATOR_BLOB,
        "producer_validation_workflow_git_blob_sha": EXPECTED_WORKFLOW_BLOB,
    }
    for key, expected in expected_blobs.items():
        require(details.get(key) == expected, f"unexpected producer blob for {key}")
        require(immutable_sha(details.get(key)), f"{key} must be immutable")

    require(details.get("producer_validation_run_id") == EXPECTED_VALIDATION_RUN, "unexpected producer validation run")
    require(details.get("producer_validation_run_number") == EXPECTED_VALIDATION_RUN_NUMBER, "unexpected producer validation run number")
    require(details.get("producer_validation_conclusion") == "success", "producer validation must have succeeded")
    require(details.get("state_provider_production_acceptance_records") == 0, "source evidence must not invent state-provider production acceptance")
    require(details.get("signing_provider_production_acceptance_records") == 0, "source evidence must not invent signing-provider production acceptance")
    require(details.get("state_provider_candidate_evaluation_records") == 1, "expected exactly one state-provider candidate evaluation")
    require(details.get("signing_provider_candidate_evaluation_records") == 1, "expected exactly one draft signing-provider candidate evaluation")
    require(details.get("complete_provider_candidate_evaluations") == 0, "source evidence must not invent complete provider evaluations")
    require(details.get("provider_evidence_package_records") == 4, "expected exactly four reviewed provider evidence packages")
    require(details.get("provider_evidence_review_attestation_records") == 4, "expected exactly four provider evidence review attestations")
    require(details.get("approved_provider_selection_records") == 0, "source evidence must not invent approved provider selections")
    require(details.get("provider_access_control_assessment_records") == 0, "source evidence must not invent provider access-control assessments")
    require(details.get("provider_access_control_assessment_is_production_acceptance") is False, "access-control assessment must not equal production acceptance")

    for key in (
        "full_record_status_validation_required",
        "malformed_status_fails_closed",
        "expired_status_fails_closed",
        "future_dated_status_fails_closed",
        "unsafe_privacy_status_fails_closed",
        "runtime_acceptance_required",
        "producer_authority_preserved",
        "provider_acceptance_exact_selection_decision_binding_required",
        "provider_access_control_assessment_future_dated_fails_closed",
        "provider_access_control_assessment_filename_matches_identity_required",
        "provider_access_control_assessment_duplicate_identity_fails_closed",
    ):
        require(details.get(key) is True, f"missing required source invariant: {key}")

    remaining = set(record.get("runtime_acceptance_requirements_remaining") or [])
    required_remaining = {
        "real_privacy_shield_runtime_acceptance",
        "real_state_provider_selection_and_production_acceptance",
        "real_signing_provider_selection_and_production_acceptance",
        "deployed_identity_and_authenticated_transport_acceptance",
        "shared_interaction_target_environment_acceptance",
        "independent_wardveil_runtime_acceptance",
    }
    require(required_remaining.issubset(remaining), "runtime acceptance remainder is incomplete")

    doc = DOC.read_text(encoding="utf-8").lower()
    for phrase in (
        "producer-source provenance",
        "source evidence does not establish runtime acceptance",
        "provider production acceptance remains unaccepted",
        "shared interaction",
        "protected by wardveil",
    ):
        require(phrase in doc, f"Privacy Shield documentation missing producer-source boundary: {phrase}")

    print(
        "Wardveil Privacy Shield producer-source evidence validation passed for exact producer "
        f"{EXPECTED_REVISION}; runtime/provider production acceptance remains unaccepted."
    )


if __name__ == "__main__":
    main()
