#!/usr/bin/env python3
from __future__ import annotations

import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_trust_posture_v2 import evaluate_trust_posture

NOW = "2026-09-12T04:55:00Z"


def fixture() -> dict:
    return {
        "schema_version": "0.1.0",
        "subject_id": "subject-1",
        "device_id": "device-1",
        "session_id": "session-1",
        "runtime_id": "runtime-1",
        "application_id": "goreecloud-manager",
        "action": "security.status.read",
        "impact": "medium",
        "observed_at": "2026-09-12T04:50:00Z",
        "expires_at": "2026-09-12T05:05:00Z",
        "inputs": [
            {
                "id": "identity-auth-strength",
                "state": "present",
                "authority": "goreecloud-identity",
                "evidence_reference": "evidence+sha256:identity",
            },
            {
                "id": "runtime-integrity",
                "state": "present",
                "authority": "wardveil",
                "evidence_reference": "evidence+sha256:runtime",
            },
        ],
        "reevaluation_triggers": {},
        "proposed_state": "trusted",
    }


def main() -> int:
    result = evaluate_trust_posture(fixture(), evaluated_at=NOW)
    assert result["trust_state"] == "trusted"
    assert result["authorization_effect"] is False
    assert result["execution_authorization"] is False
    assert result["target_authority"] is False
    assert result["global_trust"] is False

    missing = fixture()
    missing["inputs"][0]["state"] = "missing"
    missing["inputs"][0]["evidence_reference"] = None
    result = evaluate_trust_posture(missing, evaluated_at=NOW)
    assert result["trust_state"] == "unknown"
    assert "input_missing:identity-auth-strength" in result["reason_codes"]

    revoked = fixture()
    revoked["reevaluation_triggers"] = {"session_revoked": True}
    result = evaluate_trust_posture(revoked, evaluated_at=NOW)
    assert result["trust_state"] == "reauthentication_required"

    compromised = fixture()
    compromised["reevaluation_triggers"] = {"credential_compromised": True}
    result = evaluate_trust_posture(compromised, evaluated_at=NOW)
    assert result["trust_state"] == "untrusted"

    changed = fixture()
    changed["reevaluation_triggers"] = {"material_posture_changed": True}
    result = evaluate_trust_posture(changed, evaluated_at=NOW)
    assert result["trust_state"] == "restricted"

    already_untrusted = fixture()
    already_untrusted["proposed_state"] = "untrusted"
    already_untrusted["reevaluation_triggers"] = {"material_posture_changed": True}
    result = evaluate_trust_posture(already_untrusted, evaluated_at=NOW)
    assert result["trust_state"] == "untrusted"
    assert "proposed_untrusted_state_preserved" in result["reason_codes"]

    untrusted_with_missing_evidence = fixture()
    untrusted_with_missing_evidence["proposed_state"] = "untrusted"
    untrusted_with_missing_evidence["inputs"][0]["state"] = "missing"
    untrusted_with_missing_evidence["inputs"][0]["evidence_reference"] = None
    result = evaluate_trust_posture(untrusted_with_missing_evidence, evaluated_at=NOW)
    assert result["trust_state"] == "untrusted"

    high_impact = fixture()
    high_impact["impact"] = "high"
    high_impact["observed_at"] = "2026-09-12T04:49:00Z"
    high_impact["expires_at"] = "2026-09-12T05:10:00Z"
    result = evaluate_trust_posture(high_impact, evaluated_at=NOW)
    assert result["trust_state"] == "unknown"
    assert "trust_evidence_too_old_for_operation" in result["reason_codes"]

    expired = fixture()
    expired["expires_at"] = "2026-09-12T04:54:00Z"
    result = evaluate_trust_posture(expired, evaluated_at=NOW)
    assert result["trust_state"] == "unknown"

    invalid = fixture()
    invalid["inputs"][1]["state"] = "invalid"
    invalid["inputs"][1]["evidence_reference"] = None
    result = evaluate_trust_posture(invalid, evaluated_at=NOW)
    assert result["trust_state"] == "untrusted"

    duplicate = fixture()
    duplicate["inputs"].append(copy.deepcopy(duplicate["inputs"][0]))
    try:
        evaluate_trust_posture(duplicate, evaluated_at=NOW)
    except ValueError as exc:
        assert "duplicate trust input" in str(exc)
    else:
        raise AssertionError("duplicate trust inputs must fail closed")

    print("Wardveil trust posture tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
