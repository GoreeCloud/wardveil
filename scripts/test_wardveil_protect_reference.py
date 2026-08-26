#!/usr/bin/env python3
"""Self-tests for the dependency-free Wardveil Protect reference executor."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_protect import ExecutorAuthority, ProtectEngine  # noqa: E402

NOW = datetime(2026, 8, 26, 15, 0, tzinfo=timezone.utc)


def policy(action: str = "block", *, valid: bool = True, authoritative: bool = True) -> dict:
    return {
        "contract_version": "0.1.0",
        "record_type": "policy_decision",
        "record_id": "policy-test",
        "correlation_id": "corr-test",
        "producer": {"id": "wardveil-policy-reference", "authoritative": authoritative},
        "scope": {"resource_type": "session", "resource_id": "session-123", "operation": "access", "principal_class": "user"},
        "observed_at": NOW.isoformat(),
        "valid_until": (NOW + timedelta(minutes=5) if valid else NOW - timedelta(seconds=1)).isoformat(),
        "evidence_refs": ["evidence:test"],
        "policy_decision": action,
    }


def main() -> None:
    engine = ProtectEngine()
    authority = ExecutorAuthority("session-control", frozenset({"block", "revoke", "warn"}), frozenset({"session"}))

    calls = []
    result = engine.execute(policy("block"), authority, idempotency_key="block-1", handler=lambda action, scope: calls.append((action, scope["resource_id"])) or True, now=NOW)
    assert result.status == "succeeded"
    assert result.action == "block"
    assert calls == [("block", "session-123")]

    replay = engine.execute(policy("block"), authority, idempotency_key="block-1", handler=lambda *_: (_ for _ in ()).throw(RuntimeError("must not replay")), now=NOW)
    assert replay is result
    assert calls == [("block", "session-123")]

    expired = ProtectEngine().execute(policy("block", valid=False), authority, idempotency_key="expired-1", handler=lambda *_: True, now=NOW)
    assert expired.status == "rejected"
    assert "expired_or_missing_policy_validity" in expired.reason_codes

    unauthorized = ProtectEngine().execute(policy("isolate"), authority, idempotency_key="unauthorized-1", handler=lambda *_: True, now=NOW)
    assert unauthorized.status == "rejected"
    assert "executor_not_authorized" in unauthorized.reason_codes

    missing_handler = ProtectEngine().execute(policy("revoke"), authority, idempotency_key="handler-1", now=NOW)
    assert missing_handler.status == "rejected"
    assert "missing_execution_handler" in missing_handler.reason_codes

    non_authoritative = ProtectEngine().execute(policy("block", authoritative=False), authority, idempotency_key="authority-1", handler=lambda *_: True, now=NOW)
    assert non_authoritative.status == "rejected"
    assert "non_authoritative_policy_record" in non_authoritative.reason_codes

    warning = ProtectEngine().execute(policy("warn"), authority, idempotency_key="warn-1", now=NOW)
    assert warning.status == "succeeded"
    assert "non_mutating_reference_action" in warning.reason_codes

    failure = ProtectEngine().execute(policy("block"), authority, idempotency_key="failure-1", handler=lambda *_: False, now=NOW)
    assert failure.status == "failed"
    assert "executor_reported_failure" in failure.reason_codes

    record = result.as_runtime_record("corr-test")
    assert record["record_type"] == "protection_action"
    assert record["policy_decision"] == "block"
    assert record["executor"] == "session-control"
    assert record["idempotency_key"] == "block-1"
    assert record["execution_status"] == "succeeded"

    print("Wardveil Protect reference tests passed.")


if __name__ == "__main__":
    main()
