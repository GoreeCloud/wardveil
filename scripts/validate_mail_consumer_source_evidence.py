#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "contracts" / "wardveil.mail.consumer-source-evidence.json"
CLAMAV_ACCEPTANCE = ROOT / "contracts" / "wardveil.clamav.runtime-acceptance.json"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"Wardveil Mail consumer evidence validation failed: {message}")


def main() -> None:
    require(EVIDENCE.is_file(), "missing Mail consumer evidence")
    require(CLAMAV_ACCEPTANCE.is_file(), "missing ClamAV runtime acceptance contract")
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    acceptance = json.loads(CLAMAV_ACCEPTANCE.read_text(encoding="utf-8"))

    require(evidence.get("consumer") == "GoreeCloud Mail", "unexpected consumer identity")
    require(evidence.get("consumer_repository") == "GoreeCloud/goreecloud-mail", "unexpected consumer repository")
    revision = evidence.get("consumer_revision")
    require(isinstance(revision, str) and re.fullmatch(r"[0-9a-f]{40}", revision) is not None, "consumer revision must be an immutable commit SHA")
    require(evidence.get("source_integration_status") == "implemented", "Mail source integration must be explicitly implemented")
    require(evidence.get("runtime_acceptance_status") == "unaccepted", "source evidence must not claim runtime acceptance")
    require(evidence.get("source_evidence_is_production_protection_claim") is False, "source evidence must not authorize a production protection claim")

    details = evidence.get("evidence") or {}
    for key in (
        "exact_revision_ci_passed",
        "attachment_digest_binding",
        "authoritative_scan_record_required",
        "clean_requires_current_unexpired_evidence",
        "unknown_and_unsupported_fail_closed",
        "quarantine_handoff_requires_explicit_executor_authority",
    ):
        require(details.get(key) is True, f"missing required source evidence: {key}")
    require(details.get("direct_clamav_access_allowed") is False, "Mail must remain engine-independent")
    require(details.get("quarantine_is_deletion") is False, "quarantine must not equal deletion")

    remaining = set(evidence.get("runtime_acceptance_requirements_remaining") or [])
    required_remaining = {
        "deployed_authenticated_mail_to_wardveil_transport",
        "deployed_clamav_daemon_and_signature_health_evidence",
        "controlled_clean_and_eicar_runtime_tests",
        "authorized_quarantine_execution_evidence",
        "privacy_shield_data_minimization_acceptance",
    }
    require(required_remaining.issubset(remaining), "runtime acceptance remainder is incomplete")
    require(acceptance.get("production_runtime_status") == "unaccepted", "ClamAV production runtime must remain unaccepted")
    require("application_consumer_integration" in set(acceptance.get("required_acceptance_evidence") or []), "ClamAV acceptance must retain application consumer evidence requirement")

    print("Wardveil GoreeCloud Mail consumer source evidence validation passed.")


if __name__ == "__main__":
    main()
