#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "contracts" / "wardveil.browser.consumer-source-evidence.json"
CLAMAV_ACCEPTANCE = ROOT / "contracts" / "wardveil.clamav.runtime-acceptance.json"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"Wardveil Browser consumer evidence validation failed: {message}")


def immutable_sha(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def main() -> None:
    require(EVIDENCE.is_file(), "missing Browser consumer evidence")
    require(CLAMAV_ACCEPTANCE.is_file(), "missing ClamAV runtime acceptance contract")
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    acceptance = json.loads(CLAMAV_ACCEPTANCE.read_text(encoding="utf-8"))

    require(evidence.get("consumer") == "GoreeCloud Browser", "unexpected consumer identity")
    require(evidence.get("consumer_repository") == "GoreeCloud/goreecloud-browser", "unexpected consumer repository")
    require(immutable_sha(evidence.get("consumer_revision")), "consumer revision must be an immutable commit SHA")
    require(immutable_sha(evidence.get("consumer_source_tree_sha")), "consumer source tree must be immutable")
    require(evidence.get("source_integration_status") == "implemented", "Browser source integration must be explicitly implemented")
    require(evidence.get("runtime_acceptance_status") == "unaccepted", "source evidence must not claim runtime acceptance")
    require(evidence.get("source_evidence_is_production_protection_claim") is False, "source evidence must not authorize a production protection claim")

    details = evidence.get("evidence") or {}
    require(immutable_sha(details.get("consumer_ci_revision")), "CI revision must be immutable")
    require(immutable_sha(details.get("consumer_ci_source_tree_sha")), "CI source tree must be immutable")
    require(details.get("consumer_ci_source_tree_sha") == evidence.get("consumer_source_tree_sha"), "merged Browser tree must match tested CI tree")
    require(details.get("consumer_ci_run_number") == 196, "unexpected Browser CI run number")
    require(details.get("consumer_ci_run_id") == 33055071231, "unexpected Browser CI run id")

    for key in (
        "exact_ci_revision_passed",
        "merged_source_tree_matches_ci_tree",
        "download_digest_binding",
        "authoritative_scan_record_required",
        "clean_requires_current_unexpired_evidence",
        "clean_requires_evidence_refs",
        "unknown_and_unsupported_fail_closed",
        "download_release_requires_clean_decision",
        "staged_content_rehashed_before_release",
        "malicious_digest_remains_blocking_after_evidence_expiry",
        "private_browsing_verification_required",
        "quarantine_handoff_requires_explicit_executor_authority",
    ):
        require(details.get(key) is True, f"missing required source evidence: {key}")

    require(details.get("private_download_queue_persistence_allowed") is False, "Private Browsing download queue state must remain non-persistent")
    require(details.get("direct_clamav_access_allowed") is False, "Browser must remain engine-independent")
    require(details.get("quarantine_is_deletion") is False, "quarantine must not equal deletion")
    require(details.get("blocked_staging_file_is_canonical_quarantine") is False, "Browser staging must not impersonate canonical Wardveil Quarantine")

    remaining = set(evidence.get("runtime_acceptance_requirements_remaining") or [])
    required_remaining = {
        "deployed_authenticated_browser_to_wardveil_transport",
        "deployed_clamav_daemon_and_signature_health_evidence",
        "controlled_clean_and_eicar_runtime_tests",
        "timeout_and_scanner_unavailable_runtime_tests",
        "concurrency_safe_staging_release_acceptance",
        "authorized_quarantine_execution_and_recovery_evidence",
        "glaze_ui_security_state_acceptance",
        "privacy_shield_data_minimization_acceptance",
    }
    require(required_remaining.issubset(remaining), "runtime acceptance remainder is incomplete")
    require(acceptance.get("production_runtime_status") == "unaccepted", "ClamAV production runtime must remain unaccepted")
    require("application_consumer_integration" in set(acceptance.get("required_acceptance_evidence") or []), "ClamAV acceptance must retain application consumer evidence requirement")

    print("Wardveil GoreeCloud Browser consumer source evidence validation passed.")


if __name__ == "__main__":
    main()
