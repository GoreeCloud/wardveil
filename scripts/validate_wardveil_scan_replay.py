#!/usr/bin/env python3
"""Validate the durable same-host Wardveil Scan replay deployment boundary."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "reference" / "wardveil_scan_replay.py"
RUNNER = ROOT / "scripts" / "serve_wardveil_scan.py"
UNIT = ROOT / "deployment" / "scan-service" / "wardveil-scan.service"
README = ROOT / "deployment" / "scan-service" / "README.md"
CONTRACT = ROOT / "contracts" / "wardveil.scan-service-transport.json"
WORKFLOW = ROOT / ".github" / "workflows" / "validate-scan-service.yml"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def tokens(text: str, required: tuple[str, ...], context: str) -> None:
    for token in required:
        require(token in text, f"{context} missing required token: {token}")


def main() -> int:
    for path in (LEDGER, RUNNER, UNIT, README, CONTRACT, WORKFLOW):
        require(path.is_file(), f"missing durable replay file: {path.relative_to(ROOT)}")

    ledger = LEDGER.read_text(encoding="utf-8")
    runner = RUNNER.read_text(encoding="utf-8")
    unit = UNIT.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    workflow = WORKFLOW.read_text(encoding="utf-8")

    tokens(
        ledger,
        (
            "class SQLiteReplayLedger",
            "BEGIN IMMEDIATE",
            "replay_entries",
            "scan_replay_store_unavailable",
            "scan_replay_cached_response_invalid",
            "scan_replay_claim_lost",
            "PRAGMA synchronous = FULL",
            "PRAGMA journal_mode = DELETE",
            "0o600",
            "scanned bytes and caller secrets are never persisted",
        ),
        "durable replay ledger",
    )

    tokens(
        runner,
        (
            "SQLiteReplayLedger",
            "InMemoryReplayLedger",
            "WARDVEIL_SCAN_REPLAY_DB",
            "database.is_absolute()",
        ),
        "Scan service runner",
    )

    tokens(
        unit,
        (
            "DynamicUser=yes",
            "StateDirectory=wardveil-scan",
            "StateDirectoryMode=0700",
            "Environment=WARDVEIL_SCAN_REPLAY_DB=/var/lib/wardveil-scan/replay.sqlite3",
            "UMask=0077",
            "ProtectSystem=strict",
        ),
        "Scan service unit",
    )

    replay = contract.get("replay_protection") or {}
    require(
        replay.get("production_unit_implementation") == "bounded-expiring-sqlite-ledger",
        "production Scan replay implementation must be SQLite",
    )
    require(
        replay.get("production_database_path") == "/var/lib/wardveil-scan/replay.sqlite3",
        "unexpected production replay database path",
    )
    require(replay.get("database_mode") == "0600", "replay database must be owner-only")
    require(replay.get("state_directory_mode") == "0700", "replay state directory must be private")
    require(replay.get("restart_durability_source_validated") is True, "restart durability source contract must be validated")
    require(replay.get("same_host_shared_state_source_validated") is True, "same-host shared replay state must be source-validated")
    require(replay.get("single_host_restart_durability_runtime_accepted") is False, "source validation must not claim runtime restart acceptance")
    require(replay.get("multi_instance_durable_replay_protection_accepted") is False, "node-local SQLite must not imply multi-instance acceptance")
    require(replay.get("raw_resource_content_persisted") is False, "replay state must not persist raw resource content")
    require(replay.get("caller_secret_persisted") is False, "replay state must not persist caller secrets")

    tokens(
        readme,
        (
            "StateDirectory=wardveil-scan",
            "WARDVEIL_SCAN_REPLAY_DB=/var/lib/wardveil-scan/replay.sqlite3",
            "exact deployed-revision acceptance test",
            "Multi-host or horizontally scaled production",
        ),
        "Scan deployment README",
    )

    tokens(
        workflow,
        (
            "reference/wardveil_scan_replay.py",
            "scripts/test_wardveil_scan_replay.py",
            "scripts/validate_wardveil_scan_replay.py",
        ),
        "Scan validation workflow",
    )

    print("Wardveil durable Scan replay deployment contract valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
