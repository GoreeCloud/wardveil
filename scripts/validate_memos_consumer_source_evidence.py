#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "contracts" / "wardveil.memos.consumer-source-evidence.json"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"Wardveil Memos consumer evidence validation failed: {message}")


def immutable_sha(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def main() -> None:
    require(EVIDENCE.is_file(), "missing Memos consumer evidence")
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))

    require(evidence.get("schema_version") == 1, "unexpected schema version")
    require(evidence.get("consumer") == "GoreeCloud Memos", "unexpected consumer identity")
    require(evidence.get("consumer_repository") == "GoreeCloud/memos", "unexpected consumer repository")
    require(immutable_sha(evidence.get("consumer_revision")), "consumer revision must be immutable")
    require(immutable_sha(evidence.get("consumer_source_tree_sha")), "consumer source tree must be immutable")
    require(evidence.get("integration") == "Wardveil status presentation consumer", "unexpected integration identity")
    require(evidence.get("source_integration_status") == "implemented", "Memos source integration must be explicitly implemented")
    require(evidence.get("runtime_acceptance_status") == "unaccepted", "source evidence must not claim runtime acceptance")
    require(evidence.get("source_evidence_is_production_protection_claim") is False, "source evidence must not authorize a production protection claim")

    details = evidence.get("evidence") or {}
    require(immutable_sha(details.get("consumer_ci_revision")), "CI revision must be immutable")
    require(immutable_sha(details.get("consumer_ci_source_tree_sha")), "CI source tree must be immutable")
    require(details.get("consumer_ci_revision") == evidence.get("consumer_revision"), "CI revision must match merged Memos revision")
    require(details.get("consumer_ci_source_tree_sha") == evidence.get("consumer_source_tree_sha"), "merged Memos tree must match tested CI tree")
    require(details.get("consumer_ci_run_number") == 134, "unexpected Memos CI run number")
    require(details.get("consumer_ci_run_id") == 37768527867, "unexpected Memos CI run id")
    require(details.get("status_contract_version") == "0.1.0", "unexpected Wardveil status contract version")

    for key in (
        "exact_ci_revision_passed",
        "merged_source_tree_matches_ci_tree",
        "authoritative_producer_required_for_protected",
        "current_unexpired_evidence_required_for_protected",
        "stale_unavailable_unverified_fail_closed",
        "malformed_and_future_dated_fail_closed",
        "sensitive_evidence_markers_rejected",
        "accessible_text_state_labels",
    ):
        require(details.get(key) is True, f"missing required source evidence: {key}")

    require(details.get("high_impact_execution_implemented") is False, "Memos status consumer must remain read-only")
    require(details.get("protected_by_wardveil_authorized") is False, "source evidence must not authorize Protected by Wardveil")

    remaining = set(evidence.get("runtime_acceptance_requirements_remaining") or [])
    required_remaining = {
        "deployed_authenticated_memos_to_wardveil_status_transport",
        "producer_service_identity_and_authentication",
        "live_status_freshness_and_scope_acceptance",
        "security_event_and_audit_transport",
        "glaze_ui_security_state_acceptance",
        "privacy_shield_data_minimization_acceptance",
        "wardveil_target_runtime_acceptance",
        "production_security_acceptance",
    }
    require(required_remaining.issubset(remaining), "runtime acceptance remainder is incomplete")

    print("Wardveil GoreeCloud Memos consumer source evidence validation passed.")


if __name__ == "__main__":
    main()
