#!/usr/bin/env python3
"""Run the authenticated loopback Wardveil Scan HTTP service."""

from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_scan_replay import SQLiteReplayLedger  # noqa: E402
from reference.wardveil_scan_service import (  # noqa: E402
    DEFAULT_MAX_CONCURRENT_SCANS,
    DEFAULT_REPLAY_MAX_ENTRIES,
    DEFAULT_REPLAY_TTL_SECONDS,
    DEFAULT_SCAN_SERVICE_PORT,
    LOOPBACK_HOST,
    InMemoryReplayLedger,
    WardveilScanService,
    build_http_server,
    credentials_from_json,
)


def positive_int(name: str, default: int) -> int:
    value = int(os.environ.get(name, str(default)))
    if value < 1:
        raise ValueError(f"{name} must be positive")
    return value


def credential_file() -> Path:
    configured = os.environ.get("WARDVEIL_SCAN_CALLERS_FILE", "").strip()
    if configured:
        return Path(configured)
    credential_dir = os.environ.get("CREDENTIALS_DIRECTORY", "").strip()
    if credential_dir:
        return Path(credential_dir) / "wardveil-scan-callers.json"
    raise ValueError(
        "Wardveil Scan caller credentials require WARDVEIL_SCAN_CALLERS_FILE "
        "or systemd LoadCredential"
    )


def replay_ledger():
    max_entries = positive_int(
        "WARDVEIL_SCAN_REPLAY_MAX_ENTRIES", DEFAULT_REPLAY_MAX_ENTRIES
    )
    ttl = timedelta(
        seconds=positive_int(
            "WARDVEIL_SCAN_REPLAY_TTL_SECONDS", DEFAULT_REPLAY_TTL_SECONDS
        )
    )
    configured = os.environ.get("WARDVEIL_SCAN_REPLAY_DB", "").strip()
    if not configured:
        # Development/reference execution retains the bounded in-memory ledger.
        # The source-controlled production unit always sets WARDVEIL_SCAN_REPLAY_DB.
        return InMemoryReplayLedger(max_entries=max_entries, ttl=ttl)
    database = Path(configured)
    if not database.is_absolute():
        raise ValueError("WARDVEIL_SCAN_REPLAY_DB must be an absolute path")
    return SQLiteReplayLedger(
        path=database,
        max_entries=max_entries,
        ttl=ttl,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--port",
        type=int,
        default=int(
            os.environ.get("WARDVEIL_SCAN_SERVICE_PORT", str(DEFAULT_SCAN_SERVICE_PORT))
        ),
    )
    args = parser.parse_args()

    try:
        callers_path = credential_file()
        raw_credentials = callers_path.read_text(encoding="utf-8")
        credentials = credentials_from_json(raw_credentials)
        max_concurrent_scans = positive_int(
            "WARDVEIL_SCAN_MAX_CONCURRENT_SCANS", DEFAULT_MAX_CONCURRENT_SCANS
        )
        service = WardveilScanService(
            credentials=credentials,
            replay_ledger=replay_ledger(),
        )
        server = build_http_server(
            service,
            port=args.port,
            max_concurrent_scans=max_concurrent_scans,
        )
    except (OSError, TypeError, ValueError) as exc:
        print(f"Wardveil Scan service configuration rejected: {exc}", file=sys.stderr)
        return 2

    def stop(_signum: int, _frame: object) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    print(
        f"Wardveil Scan authenticated transport listening on {LOOPBACK_HOST}:{args.port}",
        file=sys.stderr,
    )
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
