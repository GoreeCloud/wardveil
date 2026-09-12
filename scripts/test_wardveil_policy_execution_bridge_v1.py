#!/usr/bin/env python3
"""Self-tests for the Wardveil v2 Policy -> Foundation 0.9 execution bridge."""
from __future__ import annotations

import sys
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_policy_execution_bridge_v1 import (  # noqa: E402
    BRIDGE_CONTRACT_VERSION,
    build_foundation_09_policy_record,
    create_v2_bound_execution_authorization,
    verify_v2_bound_execution_authorization,
)
from reference.wardveil_protect import ExecutorAuthority  # noqa: E402
from reference.wardveil_runtime_authorization import (  # noqa: E402
    AuthorizationReplayLedger,
    AuthorizedProtectEngine,
)

NOW = datetime(2026, 9, 11, 20, 0, tzinfo=timezone.utc)
KEY = b"wardveil-v2-bridge-reference-key"
EXECUTOR = "goreecloud-drive-quarantine-executor"


def decision(
    *,
    outcome: str = "allow",
    action: str = "quarantine",
    obligations: list[str] | None = None,
    observed_at: datetime | None = None,
    valid_until: datetime | None = None,
) -> dict:
    observed = observed_at or NOW - timedelta(seconds=5)
    expires = valid_until or NOW + timedelta(minutes=4)
    values = list(obligations or [])
    return {
        "contract_version": "0.1.0",
        "record_type": "policy_decision",
        "decision_id": "3c4a0bf5-cd98-4386-a8cb-8fb3edbf3127",
        "correlation_id": "corr-policy-execution-bridge",
        "policy": {
            "policy_id": "wardveil-quarantine-policy",
            "policy_version": "2.0-test",
            "policy_digest": "sha256:policy-test",
        },
        "actor": {"service_id": "goreecloud-drive"},
        "request": {
            "action": action,
            "target": "file-123",
            "purpose": "malware-containment",
            "scopes": ["file.quarantine"],
            "audiences": ["goreecloud-drive"],
        },
        "trust": {
            "state": "verified",
            "evidence_refs": ["evidence:identity", "evidence:scan"],
        },
        "decision": outcome,
        "reason_codes": ["malware-detected"],
        "obligations": values,
        "evidence_refs": ["evidence:policy"],
        "observed_at": observed.isoformat(),
        "valid_until": expires.isoformat(),
        "revocation": {"state": "active", "reason_code": None, "revoked_at": None},
        "execution_boundary": {
            "execution_authorization_required": True,
            "policy_decision_is_execution_authorization": False,
            "policy_decision_proves_execution_success": False,
        },
    }


def expect_raises(reason: str, fn) -> None:
    try:
        fn()
    except ValueError as exc:
        assert str(exc) == reason, (str(exc), reason)
    else:
        raise AssertionError(f"expected ValueError: {reason}")


def bridge_record(record: dict, *, obligation_evidence=None) -> dict:
    return build_foundation_09_policy_record(
        record,
        target_resource_type="file",
        evaluated_at=NOW.isoformat(),
        obligation_evidence=obligation_evidence,
    )


def main() -> None:
    record = decision()
    adapted = bridge_record(record)
    assert adapted["policy_decision"] == "quarantine"
    assert adapted["scope"]["resource_type"] == "file"
    assert adapted["scope"]["resource_id"] == "file-123"
    assert adapted["scope"]["purpose"] == "malware-containment"
    assert adapted["scope"]["scopes"] == ["file.quarantine"]
    assert adapted["scope"]["audiences"] == ["goreecloud-drive"]
    assert adapted["v2_binding"]["bridge_contract_version"] == BRIDGE_CONTRACT_VERSION
    assert adapted["v2_binding"]["decision_id"] == record["decision_id"]
    assert adapted["v2_binding"]["decision"] == "allow"
    assert adapted["v2_binding"]["request"] == record["request"]
    assert adapted["v2_binding"]["execution_boundary"]["policy_decision_is_execution_authorization"] is False

    adapted2, auth = create_v2_bound_execution_authorization(
        record,
        target_resource_type="file",
        evaluated_at=NOW.isoformat(),
        obligation_evidence={},
        signing_key=KEY,
        signing_key_id="reference-bridge-key",
        executor_id=EXECUTOR,
        idempotency_key="idem-v2-1",
        nonce="nonce-v2-1",
        now=NOW,
    )
    assert adapted2 == adapted
    assert auth.action == "quarantine"
    assert auth.scope["resource_id"] == "file-123"
    assert datetime.fromisoformat(auth.expires_at) <= datetime.fromisoformat(record["valid_until"])

    verified = verify_v2_bound_execution_authorization(
        auth,
        record,
        target_resource_type="file",
        evaluated_at=NOW.isoformat(),
        obligation_evidence={},
        signing_key=KEY,
        expected_executor_id=EXECUTOR,
        replay_ledger=AuthorizationReplayLedger(),
        now=NOW,
    )
    assert verified.accepted and verified.reason == "validated_execution_authorization"

    naive_now = datetime(2026, 9, 11, 20, 0)
    expect_raises(
        "evaluation_time_must_be_timezone_aware",
        lambda: create_v2_bound_execution_authorization(
            record,
            target_resource_type="file",
            evaluated_at=NOW.isoformat(),
            obligation_evidence={},
            signing_key=KEY,
            signing_key_id="reference-bridge-key",
            executor_id=EXECUTOR,
            idempotency_key="idem-naive-clock",
            nonce="nonce-naive-clock",
            now=naive_now,
        ),
    )
    naive_verification = verify_v2_bound_execution_authorization(
        auth,
        record,
        target_resource_type="file",
        evaluated_at=NOW.isoformat(),
        obligation_evidence={},
        signing_key=KEY,
        expected_executor_id=EXECUTOR,
        replay_ledger=AuthorizationReplayLedger(),
        now=naive_now,
    )
    assert not naive_verification.accepted
    assert naive_verification.reason == "evaluation_time_must_be_timezone_aware"

    for outcome in ("deny", "require_step_up", "defer", "unknown"):
        expect_raises(
            f"policy_decision_not_enforcement_allowed:{outcome}",
            lambda outcome=outcome: bridge_record(decision(outcome=outcome)),
        )

    expect_raises(
        "policy_request_action_not_high_impact",
        lambda: bridge_record(decision(action="allow")),
    )
    for invalid_resource_type in ("", " file", "file\n"):
        expect_raises(
            "target_resource_type_required",
            lambda value=invalid_resource_type: build_foundation_09_policy_record(
                record,
                target_resource_type=value,
                evaluated_at=NOW.isoformat(),
                obligation_evidence={},
            ),
        )

    conditional = decision(
        outcome="allow_with_obligations",
        obligations=["fresh-backup-required", "audit-event-required"],
    )
    expect_raises(
        "policy_obligation_evidence_missing",
        lambda: bridge_record(conditional, obligation_evidence={"fresh-backup-required": "evidence:backup"}),
    )
    expect_raises(
        "unexpected_policy_obligation_evidence",
        lambda: bridge_record(
            conditional,
            obligation_evidence={
                "fresh-backup-required": "evidence:backup",
                "audit-event-required": "evidence:audit",
                "extra": "evidence:extra",
            },
        ),
    )
    for invalid_reference in (" evidence:backup", "evidence:backup\n", "evidence:\u0000backup"):
        expect_raises(
            "policy_obligation_evidence_invalid",
            lambda value=invalid_reference: bridge_record(
                conditional,
                obligation_evidence={
                    "fresh-backup-required": value,
                    "audit-event-required": "evidence:audit",
                },
            ),
        )
    conditional_evidence = {
        "fresh-backup-required": "evidence:backup",
        "audit-event-required": "evidence:audit",
    }
    conditional_adapted = bridge_record(conditional, obligation_evidence=conditional_evidence)
    assert conditional_adapted["v2_binding"]["obligation_evidence"] == conditional_evidence
    assert "evidence:backup" in conditional_adapted["evidence_refs"]
    assert "evidence:audit" in conditional_adapted["evidence_refs"]

    oversized_evidence = decision()
    oversized_evidence["evidence_refs"] = [f"evidence:policy:{index}" for index in range(128)]
    oversized_evidence["trust"]["evidence_refs"] = ["evidence:trust:extra"]
    expect_raises(
        "policy_evidence_reference_limit_exceeded",
        lambda: bridge_record(oversized_evidence),
    )

    revoked = decision()
    revoked["revocation"] = {
        "state": "revoked",
        "reason_code": "operator-revoked",
        "revoked_at": NOW.isoformat(),
    }
    expect_raises(
        "policy_decision_not_usable:decision_revoked",
        lambda: bridge_record(revoked),
    )

    expired = decision(valid_until=NOW - timedelta(seconds=1))
    expect_raises(
        "policy_decision_not_usable:decision_expired",
        lambda: bridge_record(expired),
    )

    future = decision(observed_at=NOW + timedelta(seconds=1))
    expect_raises(
        "policy_decision_not_usable:decision_from_future",
        lambda: bridge_record(future),
    )

    changed = deepcopy(record)
    changed["request"]["target"] = "file-999"
    changed_verification = verify_v2_bound_execution_authorization(
        auth,
        changed,
        target_resource_type="file",
        evaluated_at=NOW.isoformat(),
        obligation_evidence={},
        signing_key=KEY,
        expected_executor_id=EXECUTOR,
        replay_ledger=AuthorizationReplayLedger(),
        now=NOW,
    )
    assert not changed_verification.accepted
    assert changed_verification.reason == "policy_digest_mismatch"

    authority = ExecutorAuthority(EXECUTOR, frozenset({"quarantine"}), frozenset({"file"}))
    calls = {"count": 0}

    def handler(action: str, scope: dict) -> bool:
        calls["count"] += 1
        return action == "quarantine" and scope["resource_id"] == "file-123"

    executed = AuthorizedProtectEngine().execute(
        adapted,
        auth,
        authority,
        signing_key=KEY,
        handler=handler,
        now=NOW,
    )
    assert executed.authorization.accepted
    assert executed.protection_result is not None and executed.protection_result.status == "succeeded"
    assert calls["count"] == 1

    denied_authority = ExecutorAuthority(EXECUTOR, frozenset(), frozenset({"file"}))
    _, auth2 = create_v2_bound_execution_authorization(
        record,
        target_resource_type="file",
        evaluated_at=NOW.isoformat(),
        obligation_evidence={},
        signing_key=KEY,
        signing_key_id="reference-bridge-key",
        executor_id=EXECUTOR,
        idempotency_key="idem-v2-2",
        nonce="nonce-v2-2",
        now=NOW,
    )
    denied = AuthorizedProtectEngine().execute(
        adapted,
        auth2,
        denied_authority,
        signing_key=KEY,
        handler=handler,
        now=NOW,
    )
    assert denied.authorization.accepted
    assert denied.protection_result is not None and denied.protection_result.status == "rejected"
    assert "executor_not_authorized" in denied.protection_result.reason_codes

    assert "wardveil-v2-bridge-reference-key" not in str(adapted)
    assert "wardveil-v2-bridge-reference-key" not in str(auth.as_dict())
    print("Wardveil v2 Policy execution bridge tests passed (19 bounded cases).")


if __name__ == "__main__":
    main()
