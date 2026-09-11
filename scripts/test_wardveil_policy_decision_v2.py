#!/usr/bin/env python3
"""Behavior tests for Wardveil Work Package I policy decisions."""
from __future__ import annotations

import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))

from wardveil_policy_decision_v2 import evaluate_policy_decision, map_foundation_09_decision  # noqa: E402

NOW = "2026-09-11T18:00:00Z"


def record() -> dict:
    return {
        "contract_version": "0.1.0",
        "record_type": "policy_decision",
        "decision_id": "194f6865-2c91-4b36-ac81-f31252277635",
        "correlation_id": "corr-policy-i-001",
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
        "evidence_refs": ["evidence:scan:001", "evidence:trust:001"],
        "observed_at": "2026-09-11T17:59:00Z",
        "valid_until": "2026-09-11T18:04:00Z",
        "revocation": {"state": "active", "reason_code": None, "revoked_at": None},
        "execution_boundary": {
            "execution_authorization_required": True,
            "policy_decision_is_execution_authorization": False,
            "policy_decision_proves_execution_success": False,
        },
    }


def test_allow_is_usable_but_never_execution_authority() -> None:
    result = evaluate_policy_decision(record(), evaluated_at=NOW)
    assert result["decision_usable"] is True
    assert result["enforcement_allowed"] is True
    assert result["execution_authorization_required"] is True
    assert result["execution_authority"] is False
    assert result["execution_success_proven"] is False


def test_conditional_allow_requires_obligations() -> None:
    candidate = record()
    candidate["decision"] = "allow_with_obligations"
    result = evaluate_policy_decision(candidate, evaluated_at=NOW)
    assert result["decision_usable"] is False
    assert "conditional_allow_requires_obligations" in result["reason_codes"]


def test_conditional_allow_preserves_obligations() -> None:
    candidate = record()
    candidate["decision"] = "allow_with_obligations"
    candidate["obligations"] = ["audit_event_required", "target_state_readback_required"]
    result = evaluate_policy_decision(candidate, evaluated_at=NOW)
    assert result["decision_usable"] is True
    assert result["enforcement_allowed"] is True
    assert result["obligations"] == ["audit_event_required", "target_state_readback_required"]


def test_step_up_is_not_allow() -> None:
    candidate = record()
    candidate["decision"] = "require_step_up"
    candidate["reason_codes"] = ["stronger_identity_evidence_required"]
    result = evaluate_policy_decision(candidate, evaluated_at=NOW)
    assert result["step_up_required"] is True
    assert result["enforcement_allowed"] is False


def test_unknown_and_defer_fail_closed() -> None:
    for decision in ("unknown", "defer"):
        candidate = record()
        candidate["decision"] = decision
        candidate["reason_codes"] = [f"{decision}_required"]
        result = evaluate_policy_decision(candidate, evaluated_at=NOW)
        assert result["must_defer"] is True
        assert result["enforcement_allowed"] is False


def test_revoked_decision_fails_closed() -> None:
    candidate = record()
    candidate["revocation"] = {
        "state": "revoked",
        "reason_code": "policy_superseded",
        "revoked_at": "2026-09-11T17:59:30Z",
    }
    result = evaluate_policy_decision(candidate, evaluated_at=NOW)
    assert result["decision_usable"] is False
    assert "decision_revoked" in result["reason_codes"]


def test_revocation_before_decision_fails_closed() -> None:
    candidate = record()
    candidate["revocation"] = {
        "state": "revoked",
        "reason_code": "policy_superseded",
        "revoked_at": "2026-09-11T17:58:59Z",
    }
    result = evaluate_policy_decision(candidate, evaluated_at=NOW)
    assert result["decision_usable"] is False
    assert "revocation_before_decision" in result["reason_codes"]


def test_future_revocation_timestamp_fails_closed() -> None:
    candidate = record()
    candidate["revocation"] = {
        "state": "revoked",
        "reason_code": "policy_superseded",
        "revoked_at": "2026-09-11T18:00:01Z",
    }
    result = evaluate_policy_decision(candidate, evaluated_at=NOW)
    assert result["decision_usable"] is False
    assert "revocation_from_future" in result["reason_codes"]


def test_active_revocation_metadata_is_rejected() -> None:
    candidate = record()
    candidate["revocation"] = {
        "state": "active",
        "reason_code": "stale_metadata",
        "revoked_at": None,
    }
    result = evaluate_policy_decision(candidate, evaluated_at=NOW)
    assert result["decision_usable"] is False
    assert "active_revocation_metadata_present" in result["reason_codes"]


def test_expired_decision_fails_closed() -> None:
    candidate = record()
    candidate["valid_until"] = "2026-09-11T17:59:59Z"
    result = evaluate_policy_decision(candidate, evaluated_at=NOW)
    assert result["decision_usable"] is False
    assert "decision_expired" in result["reason_codes"]


def test_missing_target_fails_closed() -> None:
    candidate = record()
    candidate["request"]["target"] = ""
    result = evaluate_policy_decision(candidate, evaluated_at=NOW)
    assert result["decision_usable"] is False
    assert "request_target_missing" in result["reason_codes"]


def test_policy_decision_cannot_self_declare_execution_authority() -> None:
    candidate = record()
    candidate["execution_boundary"]["policy_decision_is_execution_authorization"] = True
    result = evaluate_policy_decision(candidate, evaluated_at=NOW)
    assert result["decision_usable"] is False
    assert "policy_decision_cannot_be_execution_authorization" in result["reason_codes"]


def test_foundation_quarantine_maps_to_defer() -> None:
    result = map_foundation_09_decision("quarantine")
    assert result["decision"] == "defer"
    assert result["obligations"] == ["route_to_authorized_response_path"]
    assert result["execution_authority"] is False


def test_foundation_allow_and_log_maps_to_audit_obligation() -> None:
    result = map_foundation_09_decision("allow_and_log")
    assert result["decision"] == "allow_with_obligations"
    assert result["obligations"] == ["audit_event_required"]


def test_unknown_foundation_decision_stays_unknown() -> None:
    result = map_foundation_09_decision("future_unrecognized_decision")
    assert result["decision"] == "unknown"
    assert result["execution_authority"] is False


def main() -> None:
    tests = [value for name, value in globals().items() if name.startswith("test_") and callable(value)]
    for test in sorted(tests, key=lambda fn: fn.__name__):
        test()
    print(f"passed {len(tests)} Wardveil policy-decision tests")


if __name__ == "__main__":
    main()
