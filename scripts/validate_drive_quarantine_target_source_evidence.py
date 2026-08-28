#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "contracts" / "wardveil.drive.quarantine-target-source-evidence.json"
EXECUTOR = ROOT / "contracts" / "wardveil.quarantine-executor.json"
DEPLOYMENT = ROOT / "contracts" / "wardveil.quarantine-executor-deployment.json"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def sha(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def main() -> None:
    for path in (EVIDENCE, EXECUTOR, DEPLOYMENT):
        require(path.is_file(), f"missing required evidence input: {path.relative_to(ROOT)}")

    evidence = json.loads(EVIDENCE.read_text())
    executor = json.loads(EXECUTOR.read_text())
    deployment = json.loads(DEPLOYMENT.read_text())
    detail = evidence.get("evidence") or {}

    require(evidence.get("schema_version") == 1, "unexpected Drive quarantine evidence schema")
    require(evidence.get("consumer") == "GoreeCloud Drive", "unexpected Drive consumer identity")
    require(evidence.get("consumer_repository") == "GoreeCloud/goreecloud-drive", "unexpected Drive repository")
    require(evidence.get("integration") == "Wardveil Quarantine resource-owner target", "unexpected integration identity")
    require(evidence.get("resource_type") == "drive_file", "unexpected Drive quarantine resource type")
    require(evidence.get("target_worker") == "goreecloud-drive-quarantine-target", "unexpected Drive target Worker")
    require(evidence.get("source_integration_status") == "implemented", "Drive target source integration must be implemented")
    require(evidence.get("runtime_acceptance_status") == "unaccepted", "Drive target runtime must remain unaccepted")

    require(sha(evidence.get("consumer_revision")), "merged Drive revision must be immutable SHA")
    require(sha(evidence.get("consumer_source_tree_sha")), "merged Drive tree must be immutable SHA")
    require(sha(detail.get("consumer_ci_revision")), "Drive CI revision must be immutable SHA")
    require(sha(detail.get("consumer_ci_source_tree_sha")), "Drive CI tree must be immutable SHA")
    require(detail.get("consumer_ci_run_number") == 41, "unexpected Drive quarantine target CI run")
    require(detail.get("consumer_pull_request") == 23, "unexpected Drive quarantine target PR")
    require(detail.get("exact_ci_revision_passed") is True, "Drive target exact CI revision must have passed")
    require(detail.get("merged_source_tree_matches_ci_tree") is True, "Drive merged tree must match CI tree")
    require(evidence.get("consumer_source_tree_sha") == detail.get("consumer_ci_source_tree_sha"), "Drive merged/CI tree mismatch")

    required_true = [
        "drive_remains_resource_authority",
        "wardveil_bridge_is_transport_only",
        "pending_state_precedes_quarantine_side_effect",
        "exact_operation_replay_is_idempotent",
        "conflicting_operation_fails_closed",
        "ambiguous_payload_state_requires_reconciliation",
        "dedicated_drive_service_authorization_required",
        "missing_drive_service_authorization_fails_closed",
        "privacy_shield_data_minimization_preserved",
        "everkeep_recovery_authority_preserved",
    ]
    for key in required_true:
        require(detail.get(key) is True, f"Drive quarantine source invariant must be true: {key}")

    required_false = [
        "target_public_http_mutation_allowed",
        "workers_dev_enabled",
        "preview_urls_enabled",
        "quarantine_is_deletion",
        "target_worker_deployed",
        "drive_backend_production_target_deployed",
        "controlled_authorized_quarantine_mutation_verified",
    ]
    for key in required_false:
        require(detail.get(key) is False, f"Drive quarantine source/deployment boundary must be false: {key}")

    remaining = set(evidence.get("runtime_acceptance_requirements_remaining") or [])
    required_remaining = {
        "deploy_drive_backend_at_approved_security_boundary",
        "deploy_goreecloud_drive_quarantine_target_worker",
        "deploy_wardveil_quarantine_executor_bound_to_drive_target_and_drive_file_only",
        "approved_production_authorization_signature_verification_and_key_management",
        "production_service_identity_and_least_privilege_binding_acceptance",
        "controlled_disposable_drive_quarantine_mutation_and_exact_readback",
        "target_and_executor_replay_idempotency_runtime_tests",
        "timeout_crash_conflict_ambiguous_outcome_and_reconciliation_exercises",
        "wardveil_audit_and_security_center_runtime_evidence",
        "quarantine_release_and_recovery_evidence",
        "privacy_shield_runtime_acceptance",
        "everkeep_recovery_acceptance",
    }
    require(required_remaining <= remaining, "Drive quarantine runtime remainder is incomplete")
    require(evidence.get("source_evidence_is_deployment_claim") is False, "source evidence must not claim deployment")
    require(evidence.get("source_evidence_is_production_protection_claim") is False, "source evidence must not claim protection")

    executor_resource_types = set(executor.get("initial_resource_types") or [])
    require("drive_file" in executor_resource_types, "Wardveil executor must retain drive_file integration scope")
    require(executor.get("production_runtime_status") == "unaccepted", "Wardveil executor must remain runtime-unaccepted")
    require((executor.get("target_adapter") or {}).get("deployment_target_is_source_placeholder") is True, "Wardveil executor source target must remain a placeholder")
    require(deployment.get("production_runtime_status") == "unaccepted", "Wardveil executor deployment gate must remain runtime-unaccepted")
    require((deployment.get("deployment") or {}).get("source_placeholder_may_be_deployed") is False, "Wardveil deployment gate must reject source placeholder")
    require((deployment.get("runtime_evidence") or {}).get("workflow_can_set_acceptance_status_accepted") is False, "deployment workflow must not self-accept runtime")
    require((deployment.get("runtime_evidence") or {}).get("workflow_can_authorize_protected_by_wardveil_claim") is False, "deployment workflow must not authorize protection claim")

    print("Drive quarantine target source evidence validation passed")


if __name__ == "__main__":
    main()
