#!/usr/bin/env python3
"""Restart and fail-closed tests for Wardveil SQLite execution state."""
from __future__ import annotations

import os
import sys
import tempfile
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_runtime_authorization import create_execution_authorization  # noqa: E402
from reference.wardveil_sqlite_execution_state import SQLiteExecutionStateStore  # noqa: E402

NOW = datetime(2026, 9, 1, 23, 58, tzinfo=timezone.utc)
KEY = b"wardveil-sqlite-execution-state-reference-key"
EXECUTOR = "goreecloud-execution-state-test"


def policy(action: str = "quarantine") -> dict:
    return {
        "contract_version": "0.1.0",
        "record_type": "policy_decision",
        "record_id": "policy-sqlite-execution-state-test",
        "correlation_id": "corr-sqlite-execution-state-test",
        "producer": {"id": "wardveil-policy-reference", "authoritative": True},
        "scope": {"resource_type": "drive.file", "resource_id": "file-sqlite-state-1"},
        "observed_at": NOW.isoformat(),
        "valid_until": (NOW + timedelta(minutes=4)).isoformat(),
        "evidence_refs": ["evidence:scan:sqlite-1"],
        "policy_decision": action,
    }


def auth(*, nonce: str = "nonce-sqlite-1", idem: str = "idem-sqlite-1"):
    return create_execution_authorization(
        policy(),
        signing_key=KEY,
        executor_id=EXECUTOR,
        idempotency_key=idem,
        nonce=nonce,
        now=NOW,
    )


def protection_record(authorization, *, record_id: str = "protect-sqlite-1") -> dict:
    return {
        "contract_version": "0.1.0",
        "record_type": "protection_action",
        "record_id": record_id,
        "correlation_id": "corr-sqlite-execution-state-test",
        "producer": {"id": "wardveil-protect-reference", "authoritative": True},
        "scope": {"resource_type": "drive.file", "resource_id": "file-sqlite-state-1"},
        "observed_at": NOW.isoformat(),
        "valid_until": (NOW + timedelta(minutes=4)).isoformat(),
        "evidence_refs": ["evidence:scan:sqlite-1"],
        "policy_decision": authorization.action,
        "executor": EXECUTOR,
        "idempotency_key": authorization.idempotency_key,
        "execution_status": "succeeded",
    }


def expect_raises(reason: str, fn) -> None:
    try:
        fn()
    except ValueError as exc:
        assert str(exc) == reason, (str(exc), reason)
    else:
        raise AssertionError(f"expected ValueError: {reason}")


def main() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = Path(temp_dir) / "execution-state.sqlite3"
        authorization = auth()

        first_store = SQLiteExecutionStateStore(db_path)
        first = first_store.claim(authorization.as_dict(), now=NOW)
        assert first.status == "new" and first.claim is not None
        assert db_path.exists()
        if os.name == "posix":
            assert db_path.stat().st_mode & 0o077 == 0

        restarted_store = SQLiteExecutionStateStore(db_path)
        pending = restarted_store.claim(authorization.as_dict(), now=NOW)
        assert pending.status == "execution_reconciliation_required"
        assert pending.claim is not None
        assert pending.claim.authorization_digest_sha256 == first.claim.authorization_digest_sha256

        conflicting_nonce = replace(authorization, authorization_id="authz-sqlite-conflict")
        assert (
            restarted_store.claim(conflicting_nonce.as_dict(), now=NOW).status
            == "authorization_nonce_conflict"
        )

        second_authorization = auth(nonce="nonce-sqlite-2", idem=authorization.idempotency_key)
        assert (
            restarted_store.claim(second_authorization.as_dict(), now=NOW).status
            == "executor_idempotency_conflict"
        )

        record = protection_record(authorization)
        receipt = restarted_store.finalize(authorization.as_dict(), record, now=NOW)
        assert receipt.outcome == "succeeded"
        assert len(receipt.receipt_digest_sha256) == 64

        second_restart = SQLiteExecutionStateStore(db_path)
        finalized = second_restart.claim(authorization.as_dict(), now=NOW)
        assert finalized.status == "idempotent_finalized"
        assert finalized.receipt == receipt
        assert second_restart.receipt(authorization.nonce) == receipt

        same_receipt = second_restart.finalize(
            authorization.as_dict(), record, now=NOW + timedelta(seconds=30)
        )
        assert same_receipt == receipt

        expect_raises(
            "execution_receipt_conflict",
            lambda: second_restart.finalize(
                authorization.as_dict(),
                protection_record(authorization, record_id="protect-sqlite-conflict"),
                now=NOW + timedelta(seconds=30),
            ),
        )

        serialized = str(receipt.as_dict()).lower()
        for forbidden in (
            "signing_key",
            "private_key",
            "password",
            "access_token",
            "refresh_token",
            "session_token",
            "cookie",
            "authorization_header",
        ):
            assert forbidden not in serialized

    print("Wardveil SQLite execution-state restart tests passed.")


if __name__ == "__main__":
    main()
