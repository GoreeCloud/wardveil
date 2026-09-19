#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_security_center_v2 import AREAS, build_security_center_snapshot, can_present_protected

NOW = "2026-09-10T18:30:00Z"


def privacy_minimization(**overrides):
    record = {
        "raw_private_content_included": False,
        "raw_private_activity_included": False,
        "reusable_credentials_included": False,
        "recovery_material_included": False,
        "unrestricted_diagnostic_payloads_included": False,
        "identifier_scope": "necessary_bounded",
        "privacy_shield_review_required": True,
    }
    record.update(overrides)
    return record


def security(**overrides):
    record = {
        "security_state": "protected",
        "resource_scope": "drive:space:primary:file:42",
        "observed_at": "2026-09-10T18:20:00Z",
        "valid_until": "2026-09-10T19:20:00Z",
        "producer": "wardveil-security",
        "reason_code": "verified_protection",
        "summary": "Current authoritative evidence supports the bounded protection state.",
        "next_action": "Continue normal monitoring.",
        "protective_execution_requested": True,
        "protective_execution_verified": True,
        "reconciliation_required": False,
        "claim_authority": True,
        "privacy_minimization": privacy_minimization(),
    }
    record.update(overrides)
    return record


def coverage(**overrides):
    record = {
        "coverage_state": "covered",
        "resource_scope": "drive:space:primary:file:42",
        "production_accepted": True,
    }
    record.update(overrides)
    return record


def expect_error(fn, needle):
    try:
        fn()
    except ValueError as exc:
        assert needle in str(exc), (needle, str(exc))
    else:
        raise AssertionError(f"expected ValueError containing {needle!r}")


def test_protected_requires_complete_evidence_chain():
    snapshot = build_security_center_snapshot(security(), coverage(), generated_at=NOW)
    assert snapshot["security_state"] == "protected"
    assert can_present_protected(snapshot)
    assert snapshot["coverage_state"] == "covered"
    assert snapshot["areas"] == list(AREAS)
    assert snapshot["why_this_status"]["evidence_valid"] is True


def test_source_only_coverage_cannot_present_protected():
    snapshot = build_security_center_snapshot(
        security(), coverage(production_accepted=False), generated_at=NOW
    )
    assert snapshot["security_state"] == "unknown"
    assert snapshot["claim_authority"] is False
    assert snapshot["why_this_status"]["reason_code"] == "security_center_protection_claim_unproven"


def test_expired_evidence_fails_closed():
    snapshot = build_security_center_snapshot(
        security(valid_until="2026-09-10T18:29:59Z"), coverage(), generated_at=NOW
    )
    assert snapshot["security_state"] == "unknown"
    assert snapshot["claim_authority"] is False
    assert snapshot["why_this_status"]["evidence_valid"] is False


def test_unverified_execution_cannot_present_protected():
    snapshot = build_security_center_snapshot(
        security(protective_execution_verified=False), coverage(), generated_at=NOW
    )
    assert snapshot["security_state"] == "unknown"
    assert snapshot["claim_authority"] is False


def test_reconciliation_uncertainty_blocks_stronger_state():
    snapshot = build_security_center_snapshot(
        security(
            security_state="degraded",
            reconciliation_required=True,
            claim_authority=False,
            reason_code="executor_timeout",
        ),
        coverage(),
        generated_at=NOW,
    )
    assert snapshot["security_state"] == "reconciliation_required"
    assert snapshot["why_this_status"]["reconciliation_required"] is True


def test_nonprotected_state_never_gets_claim_authority():
    snapshot = build_security_center_snapshot(
        security(security_state="contained", claim_authority=True), coverage(), generated_at=NOW
    )
    assert snapshot["security_state"] == "contained"
    assert snapshot["claim_authority"] is False


def test_future_evidence_is_rejected():
    expect_error(
        lambda: build_security_center_snapshot(
            security(observed_at="2026-09-10T18:31:00Z"), coverage(), generated_at=NOW
        ),
        "future-dated",
    )


def test_scope_mismatch_is_rejected():
    expect_error(
        lambda: build_security_center_snapshot(
            security(), coverage(resource_scope="drive:space:other:file:42"), generated_at=NOW
        ),
        "coverage scope",
    )


def test_secret_markers_are_rejected_from_explanation_text():
    expect_error(
        lambda: build_security_center_snapshot(
            security(summary="Authorization: Bearer reusable-token"), coverage(), generated_at=NOW
        ),
        "credential material",
    )


def test_privacy_minimization_contract_is_exposed():
    snapshot = build_security_center_snapshot(security(), coverage(), generated_at=NOW)
    assert snapshot["privacy_minimization"] == privacy_minimization()


def test_missing_privacy_minimization_is_rejected():
    record = security()
    del record["privacy_minimization"]
    expect_error(
        lambda: build_security_center_snapshot(record, coverage(), generated_at=NOW),
        "privacy_minimization must be an object",
    )


def test_raw_private_content_guarantee_must_fail_closed():
    expect_error(
        lambda: build_security_center_snapshot(
            security(privacy_minimization=privacy_minimization(raw_private_content_included=True)),
            coverage(),
            generated_at=NOW,
        ),
        "raw_private_content_included must be false",
    )


def test_unbounded_identifier_scope_is_rejected():
    expect_error(
        lambda: build_security_center_snapshot(
            security(privacy_minimization=privacy_minimization(identifier_scope="unrestricted")),
            coverage(),
            generated_at=NOW,
        ),
        "identifier_scope must be necessary_bounded",
    )


def test_privacy_shield_review_requirement_cannot_be_removed():
    expect_error(
        lambda: build_security_center_snapshot(
            security(privacy_minimization=privacy_minimization(privacy_shield_review_required=False)),
            coverage(),
            generated_at=NOW,
        ),
        "privacy_shield_review_required must be true",
    )


def test_private_payload_markers_are_rejected_from_explanation_text():
    expect_error(
        lambda: build_security_center_snapshot(
            security(summary="request_body=private-message-content"),
            coverage(),
            generated_at=NOW,
        ),
        "private user content",
    )


def test_accessibility_and_appearance_metadata_are_explicit():
    snapshot = build_security_center_snapshot(
        security(),
        coverage(),
        appearance="deep_dark",
        generated_at=NOW,
        accessibility={
            "reduced_transparency": True,
            "reduced_motion": True,
            "increased_contrast": True,
            "forced_colors": True,
            "touch_assistance": True,
        },
    )
    presentation = snapshot["presentation"]
    assert presentation["appearance"] == "deep_dark"
    assert presentation["glaze_ui_version"] == "1.3.0"
    assert presentation["rollback_version"] == "1.2.0"
    assert all(
        presentation[key]
        for key in (
            "reduced_transparency",
            "reduced_motion",
            "increased_contrast",
            "forced_colors",
            "touch_assistance",
            "material_fallback",
            "performance_fallback",
        )
    )


def test_source_candidate_does_not_self_promote_runtime_acceptance():
    snapshot = build_security_center_snapshot(security(), coverage(), generated_at=NOW)
    acceptance = snapshot["acceptance"]
    assert acceptance["source_validated"] is True
    for key in (
        "rendered_visual_review",
        "accessibility_runtime",
        "live_evidence_consumption",
        "deployment_verified",
        "rollback_verified",
        "runtime_validated",
        "production_accepted",
        "stable_qualified",
    ):
        assert acceptance[key] is False


if __name__ == "__main__":
    tests = [value for name, value in globals().items() if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(f"Wardveil Security Center 2.0 reference tests passed: {len(tests)} cases")
