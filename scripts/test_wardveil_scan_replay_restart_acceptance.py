#!/usr/bin/env python3
"""Test privacy and durable-state helpers for Scan restart acceptance."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_scan_service import CallerCredential  # noqa: E402
from scripts import accept_wardveil_scan_replay_restart as acceptance  # noqa: E402


def caller() -> CallerCredential:
    return CallerCredential(
        caller_id="goreecloud-drive",
        key_id="scan-current",
        secret=b"restart-acceptance-test-secret-0123456789abcdef",
        resource_types=frozenset({"drive_file"}),
    )


def envelope(request) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "resource_id": request.resource_id,
        "resource_digest_sha256": request.digest_sha256,
        "scan_record": {
            "contract_version": "0.1.0",
            "record_id": "scan-test-restart",
            "record_type": "scan_finding",
            "correlation_id": request.correlation_id,
            "producer": {"id": "wardveil-test", "authoritative": True},
            "scope": {
                "resource_type": request.resource_type,
                "resource_id": request.resource_id,
            },
            "observed_at": now.isoformat(),
            "valid_until": (now + timedelta(minutes=1)).isoformat(),
            "result": "clean",
            "evidence_refs": ["scan-health:test"],
        },
    }


def test_signed_request_and_private_state() -> None:
    credential = caller()
    request = acceptance.signed_request(
        credential,
        acceptance.CONTROL_BODY,
        resource_type="drive_file",
    )
    assert request.resource_type == "drive_file"
    assert request.signature != "0" * 64

    with tempfile.TemporaryDirectory() as directory:
        state_path = Path(directory) / "state.json"
        fd = os.open(state_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        payload = {
            "schema": 1,
            "source_revision": "a" * 40,
            "request": request.__dict__,
            "first_response": envelope(request),
        }
        acceptance.write_state(fd, state_path, payload, secret=credential.secret)
        assert stat.S_IMODE(state_path.stat().st_mode) == 0o600
        raw = state_path.read_bytes()
        assert credential.secret not in raw
        assert acceptance.CONTROL_BODY not in raw
        assert acceptance.CONFLICT_BODY not in raw
        reloaded = acceptance.read_state(state_path)
        assert acceptance.request_from_state(reloaded) == request


def test_private_evidence_excludes_secret_and_content() -> None:
    credential = caller()
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory).resolve() / "evidence.json"
        evidence = {
            "component": "Wardveil Scan durable same-host replay restart acceptance",
            "single_host_restart_durability": "passed",
            "multi_host_replay_durability": "not_proven",
            "production_runtime_acceptance": "unaccepted",
        }
        acceptance.write_evidence(output, evidence, secret=credential.secret)
        assert stat.S_IMODE(output.stat().st_mode) == 0o600
        raw = output.read_bytes()
        assert credential.secret not in raw
        assert acceptance.CONTROL_BODY not in raw
        assert acceptance.CONFLICT_BODY not in raw
        assert json.loads(raw) == evidence


def test_replay_database_row_validation() -> None:
    credential = caller()
    request = acceptance.signed_request(
        credential,
        acceptance.CONTROL_BODY,
        resource_type="drive_file",
    )
    expected = envelope(request)

    with tempfile.TemporaryDirectory() as directory:
        state_dir = Path(directory).resolve() / "wardveil-scan"
        state_dir.mkdir(mode=0o700)
        os.chmod(state_dir, 0o700)
        database = state_dir / "replay.sqlite3"
        connection = sqlite3.connect(database)
        try:
            connection.execute(
                """
                CREATE TABLE replay_entries (
                    caller_id TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    expires_at_us INTEGER NOT NULL,
                    response_json TEXT,
                    PRIMARY KEY (caller_id, key_id, nonce)
                )
                """
            )
            expires = int(
                (datetime.now(timezone.utc) + timedelta(minutes=2)).timestamp()
                * 1_000_000
            )
            connection.execute(
                "INSERT INTO replay_entries VALUES (?, ?, ?, ?, ?, ?)",
                (
                    request.caller_id,
                    request.key_id,
                    request.nonce,
                    "b" * 64,
                    expires,
                    json.dumps(expected, sort_keys=True, separators=(",", ":")),
                ),
            )
            connection.commit()
        finally:
            connection.close()
        os.chmod(database, 0o600)

        acceptance.validate_replay_database(database, request, expected)

        os.chmod(database, 0o640)
        try:
            acceptance.validate_replay_database(database, request, expected)
        except SystemExit:
            pass
        else:
            raise AssertionError("non-private replay database mode must fail acceptance")


def main() -> int:
    test_signed_request_and_private_state()
    test_private_evidence_excludes_secret_and_content()
    test_replay_database_row_validation()
    print("Wardveil Scan replay restart acceptance helper tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
