#!/usr/bin/env python3
"""Self-tests for Wardveil runtime execution authorization."""
from __future__ import annotations

import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_protect import ExecutorAuthority  # noqa: E402
from reference.wardveil_runtime_authorization import (  # noqa: E402
    AuthorizationReplayLedger,
    AuthorizedProtectEngine,
    create_execution_authorization,
    verify_execution_authorization,
)

NOW = datetime(2026, 8, 27, 11, 0, tzinfo=timezone.utc)
KEY = b"wardveil-reference-test-key"
EXECUTOR = "goreecloud-test-executor"


def policy(action: str = "block", *, authoritative: bool = True, valid_until: datetime | None = None) -> dict:
    return {
        "contract_version": "0.1.0",
        "record_type": "policy_decision",
        "record_id": "policy-runtime-auth-test",
        "correlation_id": "corr-runtime-auth-test",
        "producer": {"id": "wardveil-policy-reference", "authoritative": authoritative},
        "scope": {
            "resource_type": "file",
            "resource_id": "file-123",
            "operation": "release",
            "principal_class": "service",
        },
        "observed_at": NOW.isoformat(),
        "valid_until": (valid_until or NOW + timedelta(minutes=4)).isoformat(),
        "evidence_refs": ["evidence:trust", "evidence:scan"],
        "policy_decision": action,
    }


def authorization(record: dict | None = None, *, nonce: str = "nonce-1", key: str = "idem-1", now: datetime = NOW):
    return create_execution_authorization(
        record or policy(),
        signing_key=KEY,
        executor_id=EXECUTOR,
        idempotency_key=key,
        nonce=nonce,
        now=now,
    )


def verify(auth, record: dict | None = None, *, ledger: AuthorizationReplayLedger | None = None, now: datetime = NOW, executor: str = EXECUTOR, signing_key: bytes = KEY):
    return verify_execution_authorization(
        auth,
        record or policy(),
        signing_key=signing_key,
        expected_executor_id=executor,
        replay_ledger=ledger or AuthorizationReplayLedger(),
        now=now,
    )


def expect_raises(reason: str, fn) -> None:
    try:
        fn()
    except ValueError as exc:
        assert str(exc) == reason, (str(exc), reason)
    else:
        raise AssertionError(f"expected ValueError: {reason}")


def main() -> None:
    record = policy()
    auth = authorization(record)
    result = verify(auth, record)
    assert result.accepted and result.reason == "validated_execution_authorization"
    assert auth.signing_key_id == "reference-static"

    tampered = replace(auth, action="quarantine")
    assert verify(tampered, record).reason == "action_binding_mismatch"

    tampered_scope = dict(auth.scope)
    tampered_scope["resource_id"] = "file-999"
    assert verify(replace(auth, scope=tampered_scope), record).reason == "scope_binding_mismatch"

    tampered_key_id = replace(auth, signing_key_id="different-key")
    assert verify(tampered_key_id, record).reason == "invalid_authorization_signature"

    changed_policy = {**record, "evidence_refs": ["evidence:changed"]}
    assert verify(auth, changed_policy).reason == "policy_digest_mismatch"

    assert verify(auth, record, executor="different-executor").reason == "executor_binding_mismatch"
    assert verify(auth, record, signing_key=b"wrong-key").reason == "invalid_authorization_signature"
    assert verify(auth, record, now=NOW + timedelta(minutes=3)).reason == "expired_authorization"

    future = authorization(record, nonce="nonce-future", now=NOW + timedelta(minutes=1))
    assert verify(future, record, now=NOW).reason == "future_dated_authorization"

    malformed = replace(auth, issued_at="not-a-time")
    assert verify(malformed, record).reason == "invalid_authorization_time"

    expect_raises(
        "invalid_authorization_ttl",
        lambda: create_execution_authorization(record, signing_key=KEY, executor_id=EXECUTOR, idempotency_key="x", nonce="x", now=NOW, ttl=timedelta(minutes=6)),
    )
    expect_raises(
        "non_authoritative_policy_record",
        lambda: create_execution_authorization(policy(authoritative=False), signing_key=KEY, executor_id=EXECUTOR, idempotency_key="x", nonce="x", now=NOW),
    )
    expect_raises(
        "expired_or_missing_policy_validity",
        lambda: create_execution_authorization(policy(valid_until=NOW - timedelta(seconds=1)), signing_key=KEY, executor_id=EXECUTOR, idempotency_key="x", nonce="x", now=NOW),
    )
    expect_raises(
        "signing_key_required",
        lambda: create_execution_authorization(record, signing_key=b"", executor_id=EXECUTOR, idempotency_key="x", nonce="x", now=NOW),
    )

    ledger = AuthorizationReplayLedger()
    first = verify(auth, record, ledger=ledger)
    second = verify(auth, record, ledger=ledger)
    assert first.accepted and second.accepted and second.idempotent_replay
    assert second.reason == "idempotent_authorization_replay"

    conflicting = authorization(record, nonce=auth.nonce, key="different-idempotency")
    assert verify(conflicting, record, ledger=ledger).reason == "authorization_nonce_conflict"

    calls = {"count": 0}
    engine = AuthorizedProtectEngine()
    authority = ExecutorAuthority(EXECUTOR, frozenset({"block"}), frozenset({"file"}))

    def handler(action: str, scope: dict) -> bool:
        calls["count"] += 1
        return action == "block" and scope["resource_id"] == "file-123"

    executed = engine.execute(record, auth, authority, signing_key=KEY, handler=handler, now=NOW)
    replayed = engine.execute(record, auth, authority, signing_key=KEY, handler=handler, now=NOW)
    assert executed.authorization.accepted and executed.protection_result.status == "succeeded"
    assert replayed.authorization.idempotent_replay and replayed.protection_result.status == "succeeded"
    assert calls["count"] == 1

    denied_authority = ExecutorAuthority(EXECUTOR, frozenset(), frozenset({"file"}))
    denied_engine = AuthorizedProtectEngine()
    denied_auth = authorization(record, nonce="nonce-denied", key="idem-denied")
    denied = denied_engine.execute(record, denied_auth, denied_authority, signing_key=KEY, handler=handler, now=NOW)
    assert denied.authorization.accepted
    assert denied.protection_result.status == "rejected"
    assert "executor_not_authorized" in denied.protection_result.reason_codes

    no_handler_engine = AuthorizedProtectEngine()
    no_handler_auth = authorization(record, nonce="nonce-no-handler", key="idem-no-handler")
    no_handler = no_handler_engine.execute(record, no_handler_auth, authority, signing_key=KEY, now=NOW)
    assert no_handler.authorization.accepted
    assert no_handler.protection_result.status == "rejected"
    assert "missing_execution_handler" in no_handler.protection_result.reason_codes

    allow_record = policy("allow")
    allow_auth = authorization(allow_record, nonce="nonce-allow", key="idem-allow")
    allow_authority = ExecutorAuthority(EXECUTOR, frozenset({"allow"}), frozenset({"file"}))
    allowed = AuthorizedProtectEngine().execute(allow_record, allow_auth, allow_authority, signing_key=KEY, now=NOW)
    assert allowed.authorization.accepted and allowed.protection_result.status == "succeeded"

    envelope = auth.as_dict()
    for forbidden_key in ("signing_key", "private_key", "password", "access_token", "session_token"):
        assert forbidden_key not in envelope
    assert "wardveil-reference-test-key" not in str(envelope)

    print("Wardveil runtime execution authorization tests passed (21 cases).")


if __name__ == "__main__":
    main()
