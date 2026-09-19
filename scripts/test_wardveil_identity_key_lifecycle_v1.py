#!/usr/bin/env python3
"""Behavior tests for Wardveil Work Package G Identity/key lifecycle acceptance."""
from __future__ import annotations

import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))

from wardveil_identity_key_lifecycle_v1 import (  # noqa: E402
    IDENTITY_AUTHORITY,
    MESH_AUDIENCE,
    MESH_PROFILE,
    PINNED_IDENTITY_REVISION,
    evaluate_identity_key_lifecycle,
)

NOW = "2026-09-10T19:00:00Z"


def record() -> dict:
    return {
        "identity_authority": IDENTITY_AUTHORITY,
        "credential_profile": MESH_PROFILE,
        "identity_revision": PINNED_IDENTITY_REVISION,
        "usage": "mesh_transport",
        "service_id": "wardveil-security",
        "intended_audience": MESH_AUDIENCE,
        "required_scopes": ["mesh.evidence.write"],
        "credential_verification": {
            "algorithm": "RS256",
            "issuer": IDENTITY_AUTHORITY,
            "audience": MESH_AUDIENCE,
            "kid": "wardveil-key-2026",
            "service_id": "wardveil-security",
            "issued_at": "2026-09-10T18:55:00Z",
            "expires_at": "2026-09-10T19:05:00Z",
            "signature_verified": True,
            "protected_header_verified": True,
            "issuer_verified": True,
            "audience_verified": True,
            "time_verified": True,
            "workload_identity_verified": True,
            "scope_verified": True,
            "kid_resolved": True,
            "key_not_revoked": True,
            "trusted_jwks_transport_verified": True,
        },
        "key_lifecycle": {
            "rsa_key_bits": 2048,
            "rsa_public_exponent": 65537,
            "jwks_media_type": "application/json",
        },
        "acceptance_evidence": {
            "profile_source_validated": True,
            "identity_production_accepted": False,
            "live_issuance_deployed": False,
            "jwks_deployed": False,
            "durable_private_key_custody_accepted": False,
            "rotation_verified": False,
            "credential_revocation_verified": False,
            "replay_protection_verified": False,
            "expiration_enforcement_verified": False,
            "key_usage_audit_verified": False,
            "emergency_revocation_verified": False,
            "runtime_validated": False,
            "request_production_acceptance": False,
        },
    }


def test_source_reference_does_not_become_production() -> None:
    result = evaluate_identity_key_lifecycle(record(), evaluated_at=NOW)
    assert result["credential_verification"]["accepted"] is True
    assert result["acceptance"]["profile_source_validated"] is True
    assert result["acceptance"]["identity_revision_pinned"] is True
    assert result["acceptance"]["production_accepted"] is False
    assert result["acceptance"]["claim_authority"] is False
    assert "production_acceptance_not_requested" in result["reason_codes"]


def test_mesh_token_is_not_direct_wardveil_execution_authority() -> None:
    candidate = record()
    candidate["usage"] = "direct_wardveil_execution"
    result = evaluate_identity_key_lifecycle(candidate, evaluated_at=NOW)
    assert result["credential_verification"]["accepted"] is False
    assert "mesh_credential_not_direct_wardveil_authority" in result["reason_codes"]


def test_invalid_signature_fails_closed() -> None:
    candidate = record()
    candidate["credential_verification"]["signature_verified"] = False
    result = evaluate_identity_key_lifecycle(candidate, evaluated_at=NOW)
    assert result["credential_verification"]["accepted"] is False
    assert "signature_unverified" in result["reason_codes"]


def test_expired_credential_fails_closed() -> None:
    candidate = record()
    candidate["credential_verification"]["issued_at"] = "2026-09-10T18:40:00Z"
    candidate["credential_verification"]["expires_at"] = "2026-09-10T18:50:00Z"
    result = evaluate_identity_key_lifecycle(candidate, evaluated_at=NOW)
    assert result["credential_verification"]["accepted"] is False
    assert "credential_expired" in result["reason_codes"]


def test_revoked_key_fails_closed() -> None:
    candidate = record()
    candidate["credential_verification"]["key_not_revoked"] = False
    result = evaluate_identity_key_lifecycle(candidate, evaluated_at=NOW)
    assert result["credential_verification"]["accepted"] is False
    assert "key_not_revoked" not in result["reason_codes"]
    assert "key_not_revoked_unverified" in result["reason_codes"]


def test_unpinned_identity_revision_fails_closed() -> None:
    candidate = record()
    candidate["identity_revision"] = "0" * 40
    result = evaluate_identity_key_lifecycle(candidate, evaluated_at=NOW)
    assert result["credential_verification"]["accepted"] is False
    assert "identity_revision_not_pinned" in result["reason_codes"]


def test_authority_fields_reject_surrounding_whitespace() -> None:
    for path in (
        ("identity_authority",),
        ("credential_profile",),
        ("identity_revision",),
        ("usage",),
        ("service_id",),
        ("intended_audience",),
        ("credential_verification", "algorithm"),
        ("credential_verification", "issuer"),
        ("credential_verification", "audience"),
        ("credential_verification", "kid"),
        ("credential_verification", "service_id"),
        ("key_lifecycle", "jwks_media_type"),
    ):
        candidate = record()
        target = candidate
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = f" {target[path[-1]]}"
        try:
            evaluate_identity_key_lifecycle(candidate, evaluated_at=NOW)
        except ValueError as exc:
            assert "leading or trailing whitespace" in str(exc)
        else:
            raise AssertionError(f"padded Identity authority field was accepted: {'.'.join(path)}")


def test_required_scopes_reject_surrounding_whitespace() -> None:
    candidate = record()
    candidate["required_scopes"] = [" mesh.evidence.write"]
    try:
        evaluate_identity_key_lifecycle(candidate, evaluated_at=NOW)
    except ValueError as exc:
        assert "without surrounding whitespace" in str(exc)
    else:
        raise AssertionError("padded required scope was accepted")


def test_production_requires_every_external_gate() -> None:
    candidate = record()
    candidate["acceptance_evidence"]["request_production_acceptance"] = True
    result = evaluate_identity_key_lifecycle(candidate, evaluated_at=NOW)
    assert result["acceptance"]["production_accepted"] is False
    assert any(code.startswith("production_gate_pending:") for code in result["reason_codes"])


def test_fully_satisfied_evidence_can_pass_reference_gate() -> None:
    candidate = record()
    candidate["acceptance_evidence"]["request_production_acceptance"] = True
    for key in list(candidate["acceptance_evidence"]):
        if key != "request_production_acceptance":
            candidate["acceptance_evidence"][key] = True
    result = evaluate_identity_key_lifecycle(candidate, evaluated_at=NOW)
    assert result["acceptance"]["production_accepted"] is True
    assert result["acceptance"]["claim_authority"] is True
    assert result["reason_codes"] == []


def test_weak_key_fails_closed() -> None:
    candidate = record()
    candidate["key_lifecycle"]["rsa_key_bits"] = 1024
    result = evaluate_identity_key_lifecycle(candidate, evaluated_at=NOW)
    assert result["credential_verification"]["accepted"] is False
    assert "identity_key_strength_unacceptable" in result["reason_codes"]


def test_oversized_lifetime_fails_closed() -> None:
    candidate = record()
    candidate["credential_verification"]["issued_at"] = "2026-09-10T18:50:00Z"
    candidate["credential_verification"]["expires_at"] = "2026-09-10T19:06:00Z"
    result = evaluate_identity_key_lifecycle(candidate, evaluated_at=NOW)
    assert result["credential_verification"]["accepted"] is False
    assert "credential_lifetime_exceeds_identity_profile" in result["reason_codes"]


def main() -> None:
    tests = [value for name, value in globals().items() if name.startswith("test_") and callable(value)]
    for test in sorted(tests, key=lambda fn: fn.__name__):
        test()
    print(f"passed {len(tests)} Wardveil Identity/key lifecycle tests")


if __name__ == "__main__":
    main()
