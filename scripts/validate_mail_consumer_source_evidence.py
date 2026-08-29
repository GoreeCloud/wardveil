#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "contracts" / "wardveil.mail.consumer-source-evidence.json"
CLAMAV_ACCEPTANCE = ROOT / "contracts" / "wardveil.clamav.runtime-acceptance.json"

EXPECTED_MAIL_REVISION = "f34d8270110b3f8f5a4e54d025d3c20cdd60735a"
EXPECTED_MAIL_CI_REVISION = "ae050ac6c2174ff914905006d46fa33fd79d9d16"
EXPECTED_MAIL_SOURCE_TREE = "54874233bc4ea0707751bb5a85f8963ff25219ac"
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

    require(evidence.get("schema_version") == 6, "unexpected Mail consumer evidence schema")
    require(evidence.get("consumer") == "GoreeCloud Mail", "unexpected consumer identity")
    require(evidence.get("consumer_repository") == "GoreeCloud/goreecloud-mail", "unexpected consumer repository")
    for field in ("consumer_revision", "consumer_ci_tested_revision", "consumer_source_tree", "source_compatible_wardveil_revision"):
        require(immutable_sha(evidence.get(field)), f"{field} must be an immutable commit SHA")
    require(evidence.get("consumer_revision") == EXPECTED_MAIL_REVISION, "Mail merged source revision drifted")
    require(evidence.get("consumer_ci_tested_revision") == EXPECTED_MAIL_CI_REVISION, "Mail exact CI revision drifted")
    require(evidence.get("consumer_source_tree") == EXPECTED_MAIL_SOURCE_TREE, "Mail tested/merged source tree drifted")
    require(evidence.get("source_compatible_wardveil_revision") == EXPECTED_WARDVEIL_TRANSPORT_REVISION, "Wardveil transport compatibility revision drifted")
    require(evidence.get("mail_integration_contract_version") == "0.5.0", "unexpected Mail Wardveil integration contract version")
    require(evidence.get("wardveil_scan_transport_contract_version") == "0.1.0", "unexpected Wardveil Scan transport contract version")
    require(
        evidence.get("source_integration_status")
        == "source_validated_bidirectional_attachment_enforcement_with_durable_application_provenance",
        "Mail source integration must record durable bidirectional application provenance",
    )
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
        "attachment_scan_provenance_store",
        "attachment_scan_provenance_tests",
        "outgoing_attachment_security_service",
        "outgoing_attachment_security_tests",
        "outgoing_attachment_scan_provenance_store",
        "outgoing_attachment_scan_provenance_tests",
        "outgoing_attachment_security_document",
        "consumer_validation_workflow",
        "consumer_ci_workflow",
    ):
        require(isinstance(details.get(path_key), str) and details.get(path_key), f"missing source path evidence: {path_key}")
    require(details.get("consumer_ci_run_number") == 496, "unexpected Mail CI run number")
    require(details.get("consumer_ci_workflow_run_id") == 33275373075, "unexpected Mail CI workflow run ID")
    require(details.get("consumer_validation_run_number") == 96, "unexpected Mail Wardveil validation run number")
    require(details.get("consumer_validation_workflow_run_id") == 33275373125, "unexpected Mail Wardveil validation workflow run ID")

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
        "durable_scan_provenance_persisted",
        "durable_scan_provenance_atomic_write",
        "durable_scan_provenance_size_bounded",
        "durable_scan_provenance_integrity_sha256",
        "durable_scan_provenance_object_id_binding",
        "durable_scan_provenance_clean_only",
        "durable_scan_provenance_restart_rehydration",
        "missing_corrupt_or_tampered_provenance_fails_closed",
        "evidence_expiry_enforced_after_restart",
        "provenance_cleanup_coordinated_with_attachment",
        "outgoing_gmail_attachment_enforcement_source_implemented",
        "outgoing_requires_wardveil_gate_when_attachments_present",
        "outgoing_non_attachment_writes_unchanged",
        "outgoing_scan_before_gmail_client_creation",
        "outgoing_only_current_clean_may_reach_provider_write",
        "outgoing_exact_authorized_bytes_serialized_to_mime",
        "outgoing_malicious_suspicious_unknown_unsupported_block_before_provider",
        "outgoing_scanner_unavailable_blocks_before_provider",
        "outgoing_resource_ids_content_bound_and_opaque",
        "outgoing_resource_ids_exclude_raw_names_content_and_user_identifiers",
        "outgoing_durable_scan_provenance_persisted",
        "outgoing_durable_scan_provenance_atomic_write",
        "outgoing_durable_scan_provenance_size_bounded",
        "outgoing_durable_scan_provenance_integrity_sha256",
        "outgoing_durable_scan_provenance_operation_id_binding",
        "outgoing_durable_scan_provenance_operation_id_opaque",
        "outgoing_durable_scan_provenance_clean_only",
        "outgoing_provenance_persistence_precedes_provider_client_creation",
        "outgoing_provenance_persistence_failure_blocks_provider_write",
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
    require(details.get("durable_scan_provenance_storage") == "private_attachment_sidecar_json", "unexpected durable provenance storage model")
    require(details.get("durable_scan_provenance_schema_version") == 1, "unexpected durable provenance schema")
    require(details.get("durable_scan_provenance_file_mode") == "0600", "durable provenance must be private")
    require(details.get("durable_scan_provenance_max_bytes") == 65536, "durable provenance size bound drifted")
    require(details.get("provenance_stores_raw_attachment_content") is False, "durable provenance must exclude raw attachment content")
    require(details.get("provenance_stores_provider_credentials") is False, "durable provenance must exclude provider credentials")
    require(details.get("provenance_stores_wardveil_caller_secrets") is False, "durable provenance must exclude Wardveil caller secrets")
    require(details.get("provenance_integrity_digest_is_production_signature") is False, "local integrity digest must not be represented as a production signature")
    require(details.get("provenance_is_wardveil_audit_ledger") is False, "application sidecar must not be represented as Wardveil Audit")
    require(details.get("production_authenticated_provenance_store_accepted") is False, "source evidence must not claim production provenance-store acceptance")
    require(details.get("automatic_rescan_after_restart_implemented") is False, "source evidence must accurately record automatic restart rescan state")

    require(set(details.get("outgoing_scan_actions") or []) == {"send", "draft"}, "outgoing Mail scan actions must remain send and draft")
    require(details.get("outgoing_durable_scan_provenance_storage") == "private_operation_sidecar_json", "unexpected outgoing provenance storage model")
    require(details.get("outgoing_durable_scan_provenance_schema_version") == 1, "unexpected outgoing provenance schema")
    require(details.get("outgoing_durable_scan_provenance_file_mode") == "0600", "outgoing provenance must be private")
    require(details.get("outgoing_durable_scan_provenance_max_bytes") == 131072, "outgoing provenance size bound drifted")
    for key in (
        "outgoing_provenance_stores_attachment_filename",
        "outgoing_provenance_stores_raw_attachment_content",
        "outgoing_provenance_stores_recipient_address",
        "outgoing_provenance_stores_provider_credentials",
        "outgoing_provenance_stores_wardveil_caller_secrets",
        "outgoing_provenance_exposes_raw_account_or_user_identifier",
        "outgoing_provenance_integrity_digest_is_production_signature",
        "outgoing_application_provenance_is_wardveil_audit",
        "outgoing_wardveil_audit_record_persisted",
        "production_authenticated_outgoing_provenance_store_accepted",
        "production_service_identity_accepted",
        "distributed_replay_protection_accepted",
        "quarantine_is_deletion",
    ):
        require(details.get(key) is False, f"outgoing provenance/acceptance boundary changed: {key}")

    remaining = set(evidence.get("runtime_acceptance_requirements_remaining") or [])
    required_remaining = {
        "deploy_hardened_wardveil_scan_service_revision",
        "deployed_mail_delivery_execution_against_hardened_wardveil_scan",
        "deployed_mail_outgoing_gmail_attachment_execution_against_hardened_wardveil_scan",
        "production_provenance_storage_permissions_lifecycle_corruption_and_recovery_acceptance",
        "production_outgoing_provenance_storage_permissions_lifecycle_corruption_and_recovery_acceptance",
        "production_goreecloud_identity_service_identity_and_key_lifecycle",
        "deployment_appropriate_durable_replay_protection",
        "current_deployed_clamav_daemon_and_signature_health_evidence",
        "controlled_clean_and_eicar_runtime_tests",
        "controlled_suspicious_and_unsupported_runtime_tests",
        "timeout_and_scanner_unavailable_runtime_tests",
        "changed_during_scan_runtime_test",
        "missing_and_tampered_provenance_runtime_tests",
        "outgoing_provenance_persistence_failure_runtime_test",
        "replay_and_capacity_exhaustion_runtime_tests",
        "credential_rotation_and_revocation_runtime_tests",
        "provider_attachment_byte_binding_evidence",
        "real_gmail_provider_attachment_acceptance",
        "application_result_and_persistence_failure_runtime_tests",
        "authorized_quarantine_execution_evidence",
        "audit_and_security_center_provenance_acceptance",
        "glaze_ui_security_state_acceptance",
        "privacy_shield_data_minimization_acceptance",
        "everkeep_backup_recovery_treatment_for_attachment_cache_and_provenance",
    }
    require(required_remaining.issubset(remaining), "runtime acceptance remainder is incomplete")
    require("durable_outgoing_scan_provenance_or_authoritative_audit_acceptance" not in remaining, "source-completed outgoing durability gate must not remain as a runtime requirement")
    require(acceptance.get("production_runtime_status") == "unaccepted", "ClamAV production runtime must remain unaccepted")
    require("application_consumer_integration" in set(acceptance.get("required_acceptance_evidence") or []), "ClamAV acceptance must retain application consumer evidence requirement")

    print("Wardveil GoreeCloud Mail durable bidirectional attachment enforcement source evidence validation passed.")


if __name__ == "__main__":
    main()
