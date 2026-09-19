#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "contracts" / "wardveil.privacy-shield.consumer-source-evidence.json"
DOC = ROOT / "PRIVACY-SHIELD.md"

EXPECTED_REVISION = "d317a9d2f16fe8aba57edb0bd7f4ef38a65fd5e1"
EXPECTED_TREE = "214f0267b81ee092fdeabc1a360ed403ba58eccc"
EXPECTED_STATUS_SCHEMA_BLOB = "f6b62576e68e19ad8b25ced5383f8a3df74716fb"
EXPECTED_STATUS_VALIDATOR_BLOB = "22dd5fb95641a663f79822c66bc8f92422064741"
EXPECTED_PROVIDER_GATE_BLOB = "23a53b5d40865159fe748348a0a178cd668dc9ff"
EXPECTED_STATE_ACCEPTANCE_SCHEMA_BLOB = "b47891772ddec46e2bf522c6a6405423e426ec2a"
EXPECTED_SIGNING_ACCEPTANCE_SCHEMA_BLOB = "4954b0ba76f8d250b2683b98c42df96eb6edf05e"
EXPECTED_WORKFLOW_BLOB = "9b4df523e500b2352d1ad68469b2874e89f0203b"
EXPECTED_STATE_CANDIDATE_BLOB = "437460bbfa76162dd56b180267cf784aa1b972b4"
EXPECTED_SIGNING_CANDIDATE_BLOB = "d0ca7ab9fa5dc4e9c9c474ee59959f83dcb52f12"
EXPECTED_STATE_PACKAGE_BLOB = "a2db264a02663663d8169688962aa0c00541f540"
EXPECTED_SIGNING_PACKAGE_BLOB = "30a88ef2b8459496650bfe3851df6b31cef5dc82"
EXPECTED_VALIDATION_RUN = 35473992314
EXPECTED_VALIDATION_RUN_NUMBER = 488
EXPECTED_STATE_OPERATIONAL_PACKAGE_BLOB = "3644d62d91af0723655e778adcf54fe1311e12c4"
EXPECTED_SIGNING_LIFECYCLE_PACKAGE_BLOB = "9e7d3ed28c363cdcf587f9b124d3eb54c58666f2"


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
        "producer_repository": "GoreeCloud/goreecloud-privacy-shield",
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
    require(details.get("state_provider_candidate_evaluation_records") == 1, "expected exactly one draft state-provider candidate evaluation")
    require(details.get("signing_provider_candidate_evaluation_records") == 1, "expected exactly one draft signing-provider candidate evaluation")
    require(details.get("complete_provider_candidate_evaluations") == 0, "source evidence must not invent complete provider evaluations")
    require(details.get("provider_evidence_package_records") == 4, "expected exactly four captured provider evidence packages")
    require(details.get("provider_evidence_review_attestation_records") == 0, "source evidence must not invent provider evidence review attestations")
    require(details.get("approved_provider_selection_records") == 0, "source evidence must not invent approved provider selections")

    for key in (
        "full_record_status_validation_required",
        "malformed_status_fails_closed",
        "expired_status_fails_closed",
        "future_dated_status_fails_closed",
        "unsafe_privacy_status_fails_closed",
        "runtime_acceptance_required",
        "producer_authority_preserved",
        "provider_acceptance_exact_selection_decision_binding_required",
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
