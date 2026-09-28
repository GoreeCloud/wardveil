#!/usr/bin/env python3
"""Self-tests for Wardveil durable execution-state and reconciliation semantics."""
from __future__ import annotations

import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_execution_reconciliation import reconcile_uncertain_execution  # noqa: E402
from reference.wardveil_execution_state import (  # noqa: E402
    DurableAuthorizedProtectCoordinator,
    InMemoryExecutionStateStore,
)
from reference.wardveil_protect import ExecutorAuthority  # noqa: E402
from reference.wardveil_runtime_authorization import create_execution_authorization  # noqa: E402

NOW = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)
KEY = b"wardveil-execution-state-reference-key"
EXECUTOR = "goreecloud-execution-state-test"


def policy(action: str = "block") -> dict:
    return {
        "contract_version": "0.1.0",
        "record_type": "policy_decision",
        "record_id": "policy-execution-state-test",
        "correlation_id": "corr-execution-state-test",
        "producer": {"id": "wardveil-policy-reference", "authoritative": True},
        "scope": {"resource_type": "file", "resource_id": "file-exec-state-1"},
        "observed_at": NOW.isoformat(),
        "valid_until": (NOW + timedelta(minutes=4)).isoformat(),
        "evidence_refs": ["evidence:scan:1"],
        "policy_decision": action,
    }


def auth(*, nonce: str = "nonce-exec-1", idem: str = "idem-exec-1", action: str = "block"):
    return create_execution_authorization(
        policy(action),
        signing_key=KEY,
        executor_id=EXECUTOR,
        idempotency_key=idem,
        nonce=nonce,
        now=NOW,
    )


def protection_record(authorization, *, outcome: str = "succeeded") -> dict:
    return {
        "contract_version": "0.1.0",
        "record_type": "protection_action",
        "record_id": "protect-execution-state-test",
        "correlation_id": "corr-execution-state-test",
        "producer": {"id": "wardveil-protect-reference", "authoritative": True},
        "scope": {"resource_type": "file", "resource_id": "file-exec-state-1"},
        "observed_at": NOW.isoformat(),
        "valid_until": (NOW + timedelta(minutes=4)).isoformat(),
        "evidence_refs": ["evidence:scan:1"],
        "policy_decision": authorization.action,
        "executor": EXECUTOR,
        "idempotency_key": authorization.idempotency_key,
        "execution_status": outcome,
    }


def expect_raises(reason: str, fn) -> None:
    try:
        fn()
    except ValueError as exc:
        assert str(exc) == reason, (str(exc), reason)
    else:
        raise AssertionError(f"expected ValueError: {reason}")


def main() -> None:
    store = InMemoryExecutionStateStore()
    authorization = auth()

    first = store.claim(authorization.as_dict(), now=NOW)
    assert first.status == "new" and first.claim is not None

    pending_retry = store.claim(authorization.as_dict(), now=NOW)
    assert pending_retry.status == "execution_reconciliation_required"
    assert pending_retry.claim is not None

    succeeded_reconciliation = reconcile_uncertain_execution(
        pending_retry.claim,
        observed_outcome="succeeded",
        evidence_ref="wardveil://operator-evidence/execution-1",
        actor_id="operator:security-admin",
        now=NOW + timedelta(seconds=30),
    )
    assert succeeded_reconciliation.resolved
    assert succeeded_reconciliation.effective_execution_state == "succeeded"
    assert not succeeded_reconciliation.new_authorization_required
    assert succeeded_reconciliation.as_dict()["original_authorization_reusable"] is False
    assert succeeded_reconciliation.as_dict()["executor_invoked"] is False

    unknown_reconciliation = reconcile_uncertain_execution(
        pending_retry.claim,
        observed_outcome="unknown",
        evidence_ref="wardveil://operator-evidence/incomplete-1",
        actor_id="operator:security-admin",
        now=NOW + timedelta(seconds=31),
    )
    assert not unknown_reconciliation.resolved
    assert unknown_reconciliation.effective_execution_state == "execution_reconciliation_required"

    not_executed = reconcile_uncertain_execution(
        pending_retry.claim,
        observed_outcome="not_executed",
        evidence_ref="wardveil://operator-evidence/not-executed-1",
        actor_id="operator:security-admin",
        now=NOW + timedelta(seconds=32),
    )
    assert not_executed.resolved and not_executed.new_authorization_required
    assert not_executed.as_dict()["original_authorization_reusable"] is False

    conflicting_nonce = replace(authorization, authorization_id="authz-conflicting")
    assert store.claim(conflicting_nonce.as_dict(), now=NOW).status == "authorization_nonce_conflict"

    second_auth = auth(nonce="nonce-exec-2", idem=authorization.idempotency_key)
    assert store.claim(second_auth.as_dict(), now=NOW).status == "executor_idempotency_conflict"

    record = protection_record(authorization)
    receipt = store.finalize(authorization.as_dict(), record, now=NOW)
    assert receipt.outcome == "succeeded"
    assert receipt.protection_record == record
    assert len(receipt.receipt_digest_sha256) == 64

    finalized_retry = store.claim(authorization.as_dict(), now=NOW)
    assert finalized_retry.status == "idempotent_finalized"
    assert finalized_retry.receipt == receipt
    assert finalized_retry.claim is not None
    expect_raises(
        "reconciliation_requires_uncertain_claim",
        lambda: reconcile_uncertain_execution(
            finalized_retry.claim,
            observed_outcome="succeeded",
            evidence_ref="wardveil://operator-evidence/already-finalized",
            actor_id="operator:security-admin",
            now=NOW,
        ),
    )

    same_receipt = store.finalize(authorization.as_dict(), record, now=NOW + timedelta(seconds=1))
    assert same_receipt == receipt

    changed_record = {**record, "record_id": "protect-conflicting"}
    expect_raises(
        "execution_receipt_conflict",
        lambda: store.finalize(authorization.as_dict(), changed_record, now=NOW),
    )

    other_store = InMemoryExecutionStateStore()
    other_auth = auth(nonce="nonce-scope", idem="idem-scope")
    assert other_store.claim(other_auth.as_dict(), now=NOW).status == "new"
    other_record = protection_record(other_auth)
    bad_scope = {**other_record, "scope": {"resource_type": "file", "resource_id": "other-file"}}
    expect_raises(
        "protection_scope_mismatch",
        lambda: other_store.finalize(other_auth.as_dict(), bad_scope, now=NOW),
    )

    expired_store = InMemoryExecutionStateStore()
    expired = auth(nonce="nonce-expired", idem="idem-expired")
    assert expired_store.claim(expired.as_dict(), now=NOW + timedelta(minutes=3)).status == "expired_authorization"

    overflow_store = InMemoryExecutionStateStore()
    overflow_auth = auth(nonce="nonce-overflow", idem="idem-overflow").as_dict()
    overflow_auth["expires_at"] = "9999-12-31T23:59:59-01:00"
    assert overflow_store.claim(overflow_auth, now=NOW).status == "expired_authorization"
    overflow_now = datetime.fromisoformat("0001-01-01T00:00:00+01:00")
    expect_raises(
        "timestamp_out_of_supported_range",
        lambda: overflow_store.claim(auth(nonce="nonce-overflow-now", idem="idem-overflow-now").as_dict(), now=overflow_now),
    )

    calls = {"count": 0}
    coordinated_store = InMemoryExecutionStateStore()
    authority = ExecutorAuthority(EXECUTOR, frozenset({"block"}), frozenset({"file"}))
    coordinated_auth = auth(nonce="nonce-coordinated", idem="idem-coordinated")

    def handler(action: str, scope: dict) -> bool:
        calls["count"] += 1
        return action == "block" and scope["resource_id"] == "file-exec-state-1"

    first_coordinator = DurableAuthorizedProtectCoordinator(state_store=coordinated_store)
    executed = first_coordinator.execute(
        policy(), coordinated_auth, authority, signing_key=KEY, handler=handler, now=NOW,
    )
    assert executed.accepted and executed.receipt is not None
    assert executed.protection_result is not None and executed.protection_result.status == "succeeded"
    assert calls["count"] == 1

    second_coordinator = DurableAuthorizedProtectCoordinator(state_store=coordinated_store)
    replayed = second_coordinator.execute(
        policy(), coordinated_auth, authority, signing_key=KEY, handler=handler, now=NOW,
    )
    assert replayed.accepted and replayed.idempotent_replay
    assert replayed.reason == "idempotent_finalized_execution"
    assert calls["count"] == 1

    uncertain_store = InMemoryExecutionStateStore()
    uncertain_auth = auth(nonce="nonce-uncertain", idem="idem-uncertain")
    assert uncertain_store.claim(uncertain_auth.as_dict(), now=NOW).status == "new"
    uncertain = DurableAuthorizedProtectCoordinator(state_store=uncertain_store).execute(
        policy(), uncertain_auth, authority, signing_key=KEY, handler=handler, now=NOW,
    )
    assert not uncertain.accepted and uncertain.reconciliation_required
    assert uncertain.reason == "execution_reconciliation_required"
    assert calls["count"] == 1

    serialized = str(receipt.as_dict()).lower() + str(succeeded_reconciliation.as_dict()).lower()
    for forbidden in (
        "signing_key", "private_key", "password", "access_token",
        "refresh_token", "session_token", "cookie", "authorization_header",
    ):
        assert forbidden not in serialized

    print("Wardveil durable execution-state and reconciliation tests passed.")


if __name__ == "__main__":
    main()
