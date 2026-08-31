#!/usr/bin/env python3
"""Exercise durable same-host Wardveil Scan replay behavior."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import sys
import tempfile
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_scan_replay import SQLiteReplayLedger  # noqa: E402
from reference.wardveil_scan_service import (  # noqa: E402
    ScanServiceRequest,
    ScanServiceRequestError,
)

NOW = datetime(2026, 8, 30, 20, 30, tzinfo=timezone.utc)


def request(*, nonce: str = "nonce-001", correlation_id: str = "corr-001") -> ScanServiceRequest:
    return ScanServiceRequest(
        caller_id="goreecloud-drive",
        key_id="scan-current",
        timestamp=NOW.isoformat(),
        nonce=nonce,
        resource_type="drive_file",
        resource_id="drive:space-1:file:node-1",
        digest_sha256="a" * 64,
        size_bytes=7,
        action="upload_finalize",
        correlation_id=correlation_id,
        signature="b" * 64,
    )


def ledger(path: Path, *, max_entries: int = 4, ttl_seconds: int = 180) -> SQLiteReplayLedger:
    return SQLiteReplayLedger(
        path=path,
        max_entries=max_entries,
        ttl=timedelta(seconds=ttl_seconds),
    )


def expect_error(code: str, fn) -> None:
    try:
        fn()
    except ScanServiceRequestError as exc:
        assert exc.code == code, (exc.code, code)
    else:
        raise AssertionError(f"expected {code}")


def test_database_is_private_and_restart_durable() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "replay.sqlite3"
        first = ledger(path)
        info = path.stat()
        assert stat.S_ISREG(info.st_mode)
        assert stat.S_IMODE(info.st_mode) == 0o600

        req = request()
        digest = "c" * 64
        response = {
            "resource_id": req.resource_id,
            "resource_digest_sha256": req.digest_sha256,
            "scan_record": {"record_id": "scan-1", "result": "clean"},
        }
        assert first.claim(req, digest, now=NOW) == ("new", None)
        first.finalize(req, digest, response, now=NOW)

        reopened = ledger(path)
        state, cached = reopened.claim(req, digest, now=NOW + timedelta(seconds=1))
        assert state == "exact_replay"
        assert cached == response


def test_pending_and_conflict_survive_reopen() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "replay.sqlite3"
        first = ledger(path)
        req = request()
        assert first.claim(req, "d" * 64, now=NOW) == ("new", None)

        reopened = ledger(path)
        assert reopened.claim(req, "d" * 64, now=NOW)[0] == "pending"
        assert reopened.claim(req, "e" * 64, now=NOW)[0] == "conflict"


def test_capacity_and_expiry_are_transactional_across_instances() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "replay.sqlite3"
        first = ledger(path, max_entries=1, ttl_seconds=1)
        second = ledger(path, max_entries=1, ttl_seconds=1)

        req1 = request()
        req2 = replace(request(), nonce="nonce-002", correlation_id="corr-002")
        assert first.claim(req1, "f" * 64, now=NOW)[0] == "new"
        assert second.claim(req2, "0" * 64, now=NOW)[0] == "capacity"
        assert second.claim(req2, "0" * 64, now=NOW + timedelta(seconds=2))[0] == "new"


def test_second_instance_observes_finalized_response() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "replay.sqlite3"
        first = ledger(path)
        second = ledger(path)
        req = request()
        digest = "1" * 64
        response = {"scan_record": {"record_id": "scan-shared", "result": "clean"}}

        assert first.claim(req, digest, now=NOW)[0] == "new"
        assert second.claim(req, digest, now=NOW)[0] == "pending"
        first.finalize(req, digest, response, now=NOW)
        state, cached = second.claim(req, digest, now=NOW)
        assert state == "exact_replay"
        assert cached == response


def test_corrupt_cached_response_fails_closed() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "replay.sqlite3"
        store = ledger(path)
        req = request()
        digest = "2" * 64
        assert store.claim(req, digest, now=NOW)[0] == "new"
        store.finalize(req, digest, {"scan_record": {"result": "clean"}}, now=NOW)

        connection = sqlite3.connect(path)
        try:
            connection.execute(
                "UPDATE replay_entries SET response_json = ? WHERE nonce = ?",
                ("not-json", req.nonce),
            )
            connection.commit()
        finally:
            connection.close()

        expect_error(
            "scan_replay_cached_response_invalid",
            lambda: store.claim(req, digest, now=NOW),
        )


def test_ledger_rejects_unsafe_paths() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        relative = Path("relative-replay.sqlite3")
        try:
            ledger(relative)
        except ValueError:
            pass
        else:
            raise AssertionError("relative replay database path must be rejected")

        public = root / "public.sqlite3"
        public.write_bytes(b"")
        os.chmod(public, 0o644)
        try:
            ledger(public)
        except ValueError:
            pass
        else:
            raise AssertionError("group/other-readable replay database must be rejected")

        target = root / "target.sqlite3"
        target.write_bytes(b"")
        os.chmod(target, 0o600)
        link = root / "link.sqlite3"
        link.symlink_to(target)
        try:
            ledger(link)
        except ValueError:
            pass
        else:
            raise AssertionError("replay database symlink must be rejected")


def main() -> int:
    test_database_is_private_and_restart_durable()
    test_pending_and_conflict_survive_reopen()
    test_capacity_and_expiry_are_transactional_across_instances()
    test_second_instance_observes_finalized_response()
    test_corrupt_cached_response_fails_closed()
    test_ledger_rejects_unsafe_paths()
    print("Wardveil durable Scan replay ledger tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
