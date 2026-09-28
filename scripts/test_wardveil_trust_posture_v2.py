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


def assert_rejected(record: dict, expected: str) -> None:
    try:
        evaluate_trust_posture(record, evaluated_at=NOW)
    except ValueError as exc:
        assert expected in str(exc)
    else:
        raise AssertionError(f"trust posture record should have failed: {expected}")


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
    assert_rejected(duplicate, "duplicate trust input")

    wrong_schema = fixture()
    wrong_schema["schema_version"] = "0.2.0"
    assert_rejected(wrong_schema, "schema_version")

    extra_top_level = fixture()
    extra_top_level["global_override"] = True
    assert_rejected(extra_top_level, "unsupported fields")

    extra_input = fixture()
    extra_input["inputs"][0]["authorization_effect"] = True
    assert_rejected(extra_input, "unsupported fields")

    extra_trigger = fixture()
    extra_trigger["reevaluation_triggers"] = {"force_trusted": True}
    assert_rejected(extra_trigger, "unsupported fields")

    control_character = fixture()
    control_character["inputs"][0]["authority"] = "goreecloud-identity\ntrusted"
    assert_rejected(control_character, "control characters")

    overflow_observation = fixture()
    overflow_observation["observed_at"] = "0001-01-01T00:00:00+01:00"
    assert_rejected(overflow_observation, "outside the supported UTC range")
    try:
        evaluate_trust_posture(fixture(), evaluated_at="9999-12-31T23:59:59-01:00")
    except ValueError as exc:
        assert "outside the supported UTC range" in str(exc)
    else:
        raise AssertionError("evaluated_at UTC conversion overflow was accepted")

    print("Wardveil trust posture tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
