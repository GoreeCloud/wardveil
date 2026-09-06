#!/usr/bin/env python3
"""Validate Wardveil Scan liveness/readiness separation and fail-closed gating."""

from __future__ import annotations

import json
import socket
import sys
import threading
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_clamav import ClamAVConfig  # noqa: E402
from reference.wardveil_clamav_runtime import ClamAVRuntimePolicy  # noqa: E402
from reference.wardveil_scan_service import (  # noqa: E402
    HEALTH_PATH,
    READINESS_PATH,
    CallerCredential,
    WardveilScanService,
    build_http_server,
)

FIXED_NOW = datetime(2026, 9, 6, 13, 0, 0, tzinfo=timezone.utc)


class FakeClamAVClient:
    def __init__(self, mode: str = "healthy"):
        self.mode = mode
        self.config = ClamAVConfig(
            unix_socket=None,
            tcp_host="127.0.0.1",
            tcp_port=3310,
            timeout_seconds=1,
            max_stream_bytes=1024 * 1024,
            chunk_bytes=4096,
            producer_id="wardveil-scan-clamav",
        )

    def ping(self) -> bool:
        return self.mode != "unavailable"

    def version(self) -> str:
        if self.mode == "stale":
            return "ClamAV 1.4.6/27000/Sun Aug 30 13:00:00 2026"
        return "ClamAV 1.4.6/28106/Sun Sep 06 12:00:00 2026"


def service(mode: str) -> WardveilScanService:
    credential = CallerCredential(
        caller_id="goreecloud-drive",
        key_id="scan-current",
        secret=b"s" * 32,
        resource_types=frozenset({"drive_file"}),
    )
    return WardveilScanService(
        credentials={(credential.caller_id, credential.key_id): credential},
        client=FakeClamAVClient(mode),
        policy=ClamAVRuntimePolicy(
            max_signature_age=timedelta(hours=48),
            health_validity=timedelta(minutes=5),
        ),
        now=lambda: FIXED_NOW,
    )


def available_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def get(port: int, path: str) -> tuple[int, dict]:
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method="GET")
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def exercise_http(mode: str) -> tuple[tuple[int, dict], tuple[int, dict]]:
    server = build_http_server(service(mode), port=available_loopback_port())
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        return get(port, HEALTH_PATH), get(port, READINESS_PATH)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def main() -> int:
    healthy = service("healthy")
    ready, payload = healthy.readiness()
    assert ready is True
    assert payload["status"] == "ready"
    assert payload["scanner_runtime_state"] == "healthy"
    assert payload["signature_freshness"] == "current"
    assert payload["protection_claim_authority"] is False
    assert payload["production_runtime_status"] == "unaccepted"
    assert "engine_version" not in payload
    assert "database_version" not in payload

    unavailable = service("unavailable")
    ready, payload = unavailable.readiness()
    assert ready is False
    assert payload["status"] == "not_ready"
    assert payload["scanner_runtime_state"] == "unavailable"
    assert "clamd_unreachable" in payload["reason_codes"]

    stale = service("stale")
    ready, payload = stale.readiness()
    assert ready is False
    assert payload["scanner_runtime_state"] == "degraded"
    assert payload["signature_freshness"] == "stale"
    assert "signature_database_stale" in payload["reason_codes"]

    liveness, readiness = exercise_http("unavailable")
    assert liveness[0] == 200
    assert liveness[1] == {
        "component": "Wardveil Scan authenticated transport",
        "production_runtime_status": "unaccepted",
        "protection_claim_authority": False,
        "status": "ok",
    }
    assert readiness[0] == 503
    assert readiness[1]["status"] == "not_ready"

    liveness, readiness = exercise_http("healthy")
    assert liveness[0] == 200
    assert readiness[0] == 200
    assert readiness[1]["status"] == "ready"

    print("Wardveil Scan readiness validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
