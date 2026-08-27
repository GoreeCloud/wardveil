#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "contracts" / "wardveil.drive.consumer-source-evidence.json"
CLAMAV_ACCEPTANCE = ROOT / "contracts" / "wardveil.clamav.runtime-acceptance.json"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"Wardveil Drive consumer evidence validation failed: {message}")


def immutable_sha(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def main() -> None:
    require(EVIDENCE.is_file(), "missing Drive consumer evidence")
    require(CLAMAV_ACCEPTANCE.is_file(), "missing ClamAV runtime acceptance contract")
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    acceptance = json.loads(CLAMAV_ACCEPTANCE.read_text(encoding="utf-8"))

    require(evidence.get("consumer") == "GoreeCloud Drive", "unexpected consumer identity")
    require(evidence.get("consumer_repository") == "GoreeCloud/goreecloud-drive", "unexpected consumer repository")
    require(immutable_sha(evidence.get("consumer_revision")), "consumer revision must be an immutable commit SHA")
    require(immutable_sha(evidence.get("consumer_source_tree_sha")), "consumer source tree must be immutable")
    require(evidence.get("source_integration_status") == "implemented", "Drive source integration must be explicitly implemented")
    require(evidence.get("runtime_acceptance_status") == "unaccepted", "source evidence must not claim runtime acceptance")
    require(evidence.get("source_evidence_is_production_protection_claim") is False, "source evidence must not authorize a production protection claim")

    details = evidence.get("evidence") or {}
    require(immutable_sha(details.get("consumer_ci_revision")), "CI revision must be immutable")
    require(immutable_sha(details.get("consumer_ci_source_tree_sha")), "CI source tree must be immutable")
    require(details.get("consumer_ci_source_tree_sha") == evidence.get("consumer_source_tree_sha"), "merged Drive tree must match tested CI tree")
    for key in (
        "exact_ci_revision_passed",
        "merged_source_tree_matches_ci_tree",
        "file_digest_binding",
        "authoritative_scan_record_required",
        "clean_requires_current_unexpired_evidence",
        "unknown_and_unsupported_fail_closed",
        "upload_finalize_requires_clean_release_decision",
        "staged_content_rehashed_before_release",
        "quarantine_handoff_requires_explicit_executor_authority",
    ):
        require(details.get(key) is True, f"missing required source evidence: {key}")
    require(details.get("direct_clamav_access_allowed") is False, "Drive must remain engine-independent")
    require(details.get("quarantine_is_deletion") is False, "quarantine must not equal deletion")
    require(details.get("everkeep_restore_authority_replaced_by_drive") is False, "Drive must not replace Everkeep restore authority")

    remaining = set(evidence.get("runtime_acceptance_requirements_remaining") or [])
    required_remaining = {
        "deployed_authenticated_drive_to_wardveil_transport",
        "deployed_clamav_daemon_and_signature_health_evidence",
        "controlled_clean_and_eicar_runtime_tests",
        "durable_single_writer_finalization_acceptance",
        "download_open_share_runtime_enforcement_acceptance",
        "authorized_quarantine_execution_evidence",
        "everkeep_restore_path_acceptance",
        "privacy_shield_data_minimization_acceptance",
    }
    require(required_remaining.issubset(remaining), "runtime acceptance remainder is incomplete")
    require(acceptance.get("production_runtime_status") == "unaccepted", "ClamAV production runtime must remain unaccepted")
    require("application_consumer_integration" in set(acceptance.get("required_acceptance_evidence") or []), "ClamAV acceptance must retain application consumer evidence requirement")

    print("Wardveil GoreeCloud Drive consumer source evidence validation passed.")


if __name__ == "__main__":
    main()
