#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "wardveil.quarantine-executor-deployment.json"
WORKFLOW = ROOT / ".github" / "workflows" / "deploy-cloudflare-quarantine-executor.yml"
EXECUTOR_CONFIG = ROOT / "cloudflare" / "quarantine-executor" / "wrangler.jsonc"
RUNNER_CONFIG = ROOT / "cloudflare" / "quarantine-executor-acceptance-runner" / "wrangler.jsonc"
RUNNER_SOURCE = ROOT / "cloudflare" / "quarantine-executor-acceptance-runner" / "src" / "index.ts"
DOC = ROOT / "docs/QUARANTINE-EXECUTOR.md"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> None:
    for path in (CONTRACT, WORKFLOW, EXECUTOR_CONFIG, RUNNER_CONFIG, RUNNER_SOURCE, DOC):
        require(path.is_file(), f"missing quarantine deployment artifact: {path.relative_to(ROOT)}")

    contract = json.loads(CONTRACT.read_text())
    workflow = WORKFLOW.read_text()
    executor = json.loads(EXECUTOR_CONFIG.read_text())
    runner = json.loads(RUNNER_CONFIG.read_text())
    runner_source = RUNNER_SOURCE.read_text()
    doc = DOC.read_text()

    require(contract.get("contract_version") == "0.1.0", "unexpected quarantine deployment contract version")
    require(contract.get("foundation_version") == "0.9.0", "deployment gate must target Foundation 0.9")
    require(contract.get("production_runtime_status") == "unaccepted", "deployment source must remain unaccepted")

    deployment = contract.get("deployment") or {}
    for key in (
        "manual_dispatch_only",
        "main_branch_only",
        "exact_approved_revision_required",
        "generated_production_config_is_ephemeral",
    ):
        require(deployment.get(key) is True, f"missing deployment invariant: {key}")
    require(deployment.get("source_placeholder_may_be_deployed") is False, "source placeholder must never deploy")
    require(deployment.get("production_runtime_status_after_workflow") == "unaccepted", "workflow must remain unaccepted")
    require(deployment.get("pinned_wrangler_version") == "4.37.0", "unexpected Wrangler deployment version")

    target = contract.get("target_authority") or {}
    for key in (
        "target_worker_name_required_at_dispatch",
        "target_worker_must_preexist",
        "target_worker_must_not_be_wardveil_control_plane",
        "target_service_binding_required",
        "target_system_remains_resource_authority",
        "target_side_idempotency_required_for_acceptance",
        "exact_quarantine_readback_required_for_acceptance",
        "target_interface_runtime_acceptance_required",
    ):
        require(target.get(key) is True, f"missing target authority invariant: {key}")
    require(target.get("service_binding_is_target_authority") is False, "service binding must not grant target authority")

    privilege = contract.get("least_privilege") or {}
    expected_types = {"mail_attachment", "drive_file", "browser_download", "ai_artifact"}
    require(set(privilege.get("allowed_resource_types") or ()) == expected_types, "resource type allow-list drift")
    require(privilege.get("explicit_resource_type_subset_required") is True, "explicit deployment subset required")
    for key in ("empty_subset_allowed", "unknown_resource_type_allowed", "duplicate_resource_type_allowed", "all_source_resource_types_implicitly_authorized"):
        require(privilege.get(key) is False, f"least-privilege invariant drift: {key}")

    transport = contract.get("transport") or {}
    for key in (
        "cloudflare_service_binding_required",
        "target_worker_deployed_before_executor_required",
        "persistence_worker_deployed_before_executor_required",
        "post_deploy_internal_rpc_probe_required",
    ):
        require(transport.get(key) is True, f"missing transport invariant: {key}")
    for key in ("workers_dev_allowed", "preview_urls_allowed", "generic_public_execution_route_allowed", "transport_probe_may_authorize_quarantine_side_effect"):
        require(transport.get(key) is False, f"unsafe transport invariant: {key}")
    require(transport.get("transport_probe_expected_rejection") == "invalid_policy_record", "unexpected non-mutating probe contract")

    secrets = contract.get("secrets") or {}
    require(secrets.get("verification_secret_name") == "WARDVEIL_AUTH_VERIFICATION_KEY", "verification secret name drift")
    require(secrets.get("pre_provisioned_encrypted_worker_secret_required") is True, "secret must be pre-provisioned")
    for key in ("workflow_reads_secret_value", "workflow_prints_secret_value", "source_control_secret_value_allowed", "generated_config_secret_value_allowed"):
        require(secrets.get(key) is False, f"secret boundary drift: {key}")

    evidence = contract.get("runtime_evidence") or {}
    for key in (
        "revision_bound_manifest_required",
        "target_worker_existence_required",
        "persistence_worker_existence_required",
        "executor_post_deploy_existence_required",
        "internal_transport_probe_required",
        "real_quarantine_mutation_and_readback_required_for_acceptance",
        "production_signature_and_key_management_required_for_acceptance",
        "production_service_identity_and_revocation_required_for_acceptance",
        "runtime_failure_and_reconciliation_exercises_required_for_acceptance",
        "privacy_shield_acceptance_required",
        "everkeep_acceptance_required_when_applicable",
    ):
        require(evidence.get(key) is True, f"missing runtime evidence requirement: {key}")
    require(evidence.get("workflow_can_set_acceptance_status_accepted") is False, "deployment workflow must not self-accept")
    require(evidence.get("workflow_can_authorize_protected_by_wardveil_claim") is False, "deployment workflow must not authorize protection claim")

    require(executor.get("workers_dev") is False and executor.get("preview_urls") is False, "executor public routes must remain disabled")
    require(executor.get("vars", {}).get("WARDVEIL_QUARANTINE_TARGET_SERVICE") == "REPLACE_AT_DEPLOYMENT", "source target placeholder must remain canonical")
    require(executor.get("vars", {}).get("WARDVEIL_PRODUCTION_RUNTIME_STATUS") == "unaccepted", "source runtime status must remain unaccepted")
    target_bindings = [item for item in executor.get("services", []) if item.get("binding") == "WARDVEIL_QUARANTINE_TARGET"]
    require(len(target_bindings) == 1 and target_bindings[0].get("service") == "REPLACE_AT_DEPLOYMENT", "source target service binding must remain placeholder")

    for token in (
        "workflow_dispatch:",
        "expected_sha:",
        "quarantine_target_service:",
        "authorized_resource_types:",
        "environment: wardveil-production",
        "expected_sha does not match the declared Seal candidate source",
        "git merge-base --is-ancestor \"$WARDVEIL_CANDIDATE_SHA\" \"$GITHUB_SHA\"",
        "test \"$(git rev-parse HEAD)\" = \"$WARDVEIL_CANDIDATE_SHA\"",
        "REPLACE_AT_DEPLOYMENT",
        "workers/scripts",
        "required downstream Workers exist",
        "WARDVEIL_AUTH_VERIFICATION_KEY",
        "wrangler secret list",
        "wrangler deploy --config \"$GENERATED_CONFIG\"",
        "quarantine-executor-acceptance-runner",
        "invalid_policy_record",
        "real_quarantine_mutation_and_readback': 'pending'",
        "'workflow_control_revision': os.environ['GITHUB_SHA']",
        "'acceptance_status': 'unaccepted'",
        "'protected_by_wardveil_claim_authorized': False",
        "rm -f \"$GENERATED_CONFIG\"",
    ):
        require(token in workflow, f"missing deployment workflow invariant: {token}")

    forbidden_workflow_tokens = (
        "wrangler secret put",
        "WARDVEIL_PRODUCTION_RUNTIME_STATUS'] = 'accepted'",
        "acceptance_status': 'accepted'",
        "workers_dev'] = True",
        "preview_urls'] = True",
    )
    for token in forbidden_workflow_tokens:
        require(token not in workflow, f"unsafe quarantine deployment workflow token: {token}")

    require(runner.get("workers_dev") is False and runner.get("preview_urls") is False, "acceptance runner public routes must remain disabled")
    bindings = [item for item in runner.get("services", []) if item.get("binding") == "WARDVEIL_QUARANTINE_EXECUTOR"]
    require(len(bindings) == 1, "acceptance runner must have one executor binding")
    require(bindings[0].get("service") == "goreecloud-wardveil-quarantine-executor", "acceptance runner executor service drift")
    require(bindings[0].get("remote") is True, "acceptance runner must use remote service binding")
    for token in ("invalid_policy_record", "quarantine_side_effect_authorized: false", "production_runtime_status: \"unaccepted\""):
        require(token in runner_source, f"acceptance runner invariant missing: {token}")

    for phrase in (
        "deployment gate",
        "least-privilege",
        "pre-provisioned",
        "non-mutating",
        "Production runtime status remains `unaccepted`",
    ):
        require(phrase in doc, f"missing quarantine deployment documentation invariant: {phrase}")

    print("Wardveil Cloudflare quarantine executor deployment gate validation passed")


if __name__ == "__main__":
    main()
