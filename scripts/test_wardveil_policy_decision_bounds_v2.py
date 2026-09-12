#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))

from wardveil_policy_decision_v2 import evaluate_policy_decision  # noqa: E402

NOW = "2026-09-11T18:00:00Z"


def record() -> dict:
    return {
        "contract_version": "0.1.0",
        "record_type": "policy_decision",
        "decision_id": "194f6865-2c91-4b36-ac81-f31252277635",
        "correlation_id": "corr-policy-bounds-001",
        "policy": {
            "policy_id": "wardveil.drive.quarantine",
            "policy_version": "2.0.0-draft",
            "policy_digest": "sha256:policy-example",
        },
        "actor": {"subject_id": None, "service_id": "wardveil-policy"},
        "request": {
            "action": "quarantine",
            "target": "drive:file:example",
            "purpose": "malware_containment",
            "scopes": ["drive.file.quarantine"],
            "audiences": ["goreecloud-drive"],
        },
        "trust": {"state": "trusted", "evidence_refs": ["evidence:trust:001"]},
        "decision": "allow",
        "reason_codes": ["policy_requirements_satisfied"],
        "obligations": [],
        "evidence_refs": ["evidence:scan:001"],
        "observed_at": "2026-09-11T17:59:00Z",
        "valid_until": "2026-09-11T18:04:00Z",
        "revocation": {"state": "active", "reason_code": None, "revoked_at": None},
        "execution_boundary": {
            "execution_authorization_required": True,
            "policy_decision_is_execution_authorization": False,
            "policy_decision_proves_execution_success": False,
        },
    }


def test_noncanonical_uuid_text_fails_closed() -> None:
    for decision_id in (
        "194F6865-2C91-4B36-AC81-F31252277635",
        "{194f6865-2c91-4b36-ac81-f31252277635}",
    ):
        candidate = record()
        candidate["decision_id"] = decision_id
        result = evaluate_policy_decision(candidate, evaluated_at=NOW)
        assert result["decision_usable"] is False
        assert "decision_id_invalid" in result["reason_codes"]


def test_oversized_policy_evidence_list_fails_closed() -> None:
    candidate = record()
    candidate["evidence_refs"] = [f"evidence:scan:{index}" for index in range(129)]
    result = evaluate_policy_decision(candidate, evaluated_at=NOW)
    assert result["decision_usable"] is False
    assert "evidence_refs_invalid" in result["reason_codes"]


def test_oversized_scope_list_fails_closed() -> None:
    candidate = record()
    candidate["request"]["scopes"] = [f"scope.{index}" for index in range(129)]
    result = evaluate_policy_decision(candidate, evaluated_at=NOW)
    assert result["decision_usable"] is False
    assert "request_scopes_invalid" in result["reason_codes"]


def test_oversized_policy_text_fails_closed() -> None:
    candidate = record()
    candidate["correlation_id"] = "x" * 1001
    result = evaluate_policy_decision(candidate, evaluated_at=NOW)
    assert result["decision_usable"] is False
    assert "correlation_id_missing" in result["reason_codes"]


def main() -> None:
    tests = [value for name, value in globals().items() if name.startswith("test_") and callable(value)]
    for test in sorted(tests, key=lambda fn: fn.__name__):
        test()
    print(f"passed {len(tests)} Wardveil policy-decision bounds tests")


if __name__ == "__main__":
    main()
