#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "contracts" / "wardveil.mail.consumer-source-evidence.json"
CLAMAV_ACCEPTANCE = ROOT / "contracts" / "wardveil.clamav.runtime-acceptance.json"

EXPECTED_MAIL_REVISION = "b16b3742c5d48ebf5e5f2376ce5a993a2593f653"
EXPECTED_MAIL_CI_REVISION = "856049b149d31c8fc80ba0f902058bf8bfcc9348"
EXPECTED_MAIL_SOURCE_TREE = "e7b8127b19b5dc2f7274c82ba561b0c988a78e57"
EXPECTED_WARDVEIL_TRANSPORT_REVISION = "842d792c128906e70d41028e3153ea527c1d1899"
EXPECTED_SIGNATURE_FIELDS = {
    "caller_id",
    "key_id",
    "timestamp",
    "nonce",
    "action",
    "resource_type",
    "resource_id",
    "correlation_id",
    "size_bytes",
    "digest_sha256",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"Wardveil Mail consumer evidence validation failed: {message}")


def immutable_sha(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def main() -> None:
    require(EVIDENCE.is_file(), "missing Mail consumer evidence")
    require(CLAMAV_ACCEPTANCE.is_file(), "missing ClamAV runtime acceptance contract")
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    acceptance = json.loads(CLAMAV_ACCEPTANCE.read_text(encoding="utf-8"))

    require(evidence.get("schema_version") == 3, "unexpected Mail consumer evidence schema")
    require(evidence.get("consumer") == "GoreeCloud Mail", "unexpected consumer identity")
    require(evidence.get("consumer_repository") == "GoreeCloud/goreecloud-mail", "unexpected consumer repository")
    for field in ("consumer_revision", "consumer_ci_tested_revision", "consumer_source_tree", "source_compatible_wardveil_revision"):
        require(immutable_sha(evidence.get(field)), f"{field} must be an immutable commit SHA")
    require(evidence.get("consumer_revision") == EXPECTED_MAIL_REVISION, "Mail merged source revision drifted")
    require(evidence.get("consumer_ci_tested_revision") == EXPECTED_MAIL_CI_REVISION, "Mail exact CI revision drifted")
    require(evidence.get("consumer_source_tree") == EXPECTED_MAIL_SOURCE_TREE, "Mail tested/merged source tree drifted")
    require(evidence.get("source_compatible_wardveil_revision") == EXPECTED_WARDVEIL_TRANSPORT_REVISION, "Wardveil transport compatibility revision drifted")
    require(evidence.get("mail_integration_contract_version") == "0.3.0", "unexpected Mail Wardveil integration contract version")
    require(evidence.get("wardveil_scan_transport_contract_version") == "0.1.0", "unexpected Wardveil Scan transport contract version")
    require(evidence.get("source_integration_status") == "source_validated_application_enforcement", "Mail source integration must record application enforcement")
    require(evidence.get("runtime_acceptance_status") == "unaccepted", "source evidence must not claim runtime acceptance")
    require(evidence.get("source_evidence_is_production_protection_claim") is False, "source evidence must not authorize a production protection claim")

    details = evidence.get("evidence") or {}
    for path_key in (
        "consumer_contract",
        "consumer_reference",
        "consumer_transport_client",
        "consumer_transport_tests",
        "attachment_delivery_service",
        "attachment_delivery_tests",
        "consumer_validation_workflow",
        "consumer_ci_workflow",
    ):
        require(isinstance(details.get(path_key), str) and details.get(path_key), f"missing source path evidence: {path_key}")
    require(details.get("consumer_ci_run_number") == 278, "unexpected Mail CI run number")
    require(details.get("consumer_ci_workflow_run_id") == 33250577107, "unexpected Mail CI workflow run ID")
    require(details.get("consumer_validation_run_number") == 16, "unexpected Mail Wardveil validation run number")
    require(details.get("consumer_validation_workflow_run_id") == 33250577103, "unexpected Mail Wardveil validation workflow run ID")

    for key in (
        "exact_revision_ci_passed",
        "ci_tested_and_merged_tree_identical",
        "attachment_digest_binding",
        "authoritative_scan_record_required",
        "clean_requires_current_unexpired_evidence",
        "unknown_and_unsupported_fail_closed",
        "signed_transport_source_implemented",
        "transport_ipv4_loopback_only",
        "response_correlation_binding_required",
        "response_resource_binding_required",
        "response_size_bounded",
        "application_delivery_enforcement_source_implemented",
        "wardveil_scan_client_required_by_delivery_service",
        "provider_bytes_scanned_before_downloadable_storage",
        "only_current_clean_may_create_downloadable_record",
        "malicious_suspicious_unknown_unsupported_not_stored_for_download",
        "scanner_unavailable_fails_closed_before_storage",
        "stored_digest_must_match_scan_digest",
        "changed_during_scan_or_storage_fails_closed",
        "download_rechecks_scan_validity",
        "download_rechecks_stored_digest_binding",
        "restart_without_scan_provenance_fails_closed",
        "quarantine_handoff_requires_explicit_executor_authority",
    ):
        require(details.get(key) is True, f"missing required source evidence: {key}")

    require(details.get("canonical_application_result_field") == "result", "Mail must consume canonical scan_record.result")
    require(details.get("obsolete_application_result_field_rejected") == "scan_result", "Mail must reject obsolete scan_result")
    require(details.get("direct_clamav_access_allowed") is False, "Mail must remain engine-independent")
    require(details.get("transport_redirects_allowed") is False, "Mail Wardveil transport must reject redirects")
    require(details.get("transport_default_caller_id") == "goreecloud-mail", "unexpected Mail Wardveil caller identity")
    require(details.get("transport_signature_algorithm") == "HMAC-SHA256-reference-transport", "unexpected source transport signature algorithm")
    require(set(details.get("transport_signature_fields") or []) == EXPECTED_SIGNATURE_FIELDS, "Mail transport signature binding set changed")
    require(details.get("delivery_scan_action") == "download", "Mail delivery must scan for download lifecycle action")
    require(details.get("durable_scan_provenance_persisted") is False, "source evidence must not invent durable scan provenance")
    require(details.get("automatic_rescan_after_restart_implemented") is False, "source evidence must not invent automatic restart rescan")
    require(details.get("production_service_identity_accepted") is False, "source evidence must not claim production service identity acceptance")
    require(details.get("distributed_replay_protection_accepted") is False, "source evidence must not claim distributed replay protection")
    require(details.get("quarantine_is_deletion") is False, "quarantine must not equal deletion")

    remaining = set(evidence.get("runtime_acceptance_requirements_remaining") or [])
    required_remaining = {
        "deploy_hardened_wardveil_scan_service_revision",
        "deployed_mail_delivery_execution_against_hardened_wardveil_scan",
        "durable_revocable_scan_provenance_or_bounded_automatic_rescan",
        "production_goreecloud_identity_service_identity_and_key_lifecycle",
        "deployment_appropriate_durable_replay_protection",
        "current_deployed_clamav_daemon_and_signature_health_evidence",
        "controlled_clean_and_eicar_runtime_tests",
        "controlled_suspicious_and_unsupported_runtime_tests",
        "timeout_and_scanner_unavailable_runtime_tests",
        "changed_during_scan_runtime_test",
        "replay_and_capacity_exhaustion_runtime_tests",
        "credential_rotation_and_revocation_runtime_tests",
        "provider_attachment_byte_binding_evidence",
        "application_result_handling_failure_tests",
        "authorized_quarantine_execution_evidence",
        "audit_and_security_center_provenance_acceptance",
        "glaze_ui_security_state_acceptance",
        "privacy_shield_data_minimization_acceptance",
        "applicable_everkeep_behavior_acceptance",
    }
    require(required_remaining.issubset(remaining), "runtime acceptance remainder is incomplete")
    require(acceptance.get("production_runtime_status") == "unaccepted", "ClamAV production runtime must remain unaccepted")
    require("application_consumer_integration" in set(acceptance.get("required_acceptance_evidence") or []), "ClamAV acceptance must retain application consumer evidence requirement")

    print("Wardveil GoreeCloud Mail delivery-enforcement source evidence validation passed.")


if __name__ == "__main__":
    main()
