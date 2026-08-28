#!/usr/bin/env python3
"""Validate the source-controlled Wardveil authenticated Scan service boundary."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVICE = ROOT / "reference" / "wardveil_scan_service.py"
RUNNER = ROOT / "scripts" / "serve_wardveil_scan.py"
UNIT = ROOT / "deployment" / "scan-service" / "wardveil-scan.service"
ENV = ROOT / "deployment" / "scan-service" / ".env.example"
README = ROOT / "deployment" / "scan-service" / "README.md"
WORKFLOW = ROOT / ".github" / "workflows" / "validate-scan-service.yml"


def require(text: str, token: str, context: str) -> None:
    if token not in text:
        raise SystemExit(f"{context} missing required token: {token}")


def forbid(text: str, token: str, context: str) -> None:
    if token in text:
        raise SystemExit(f"{context} contains forbidden token: {token}")


def main() -> int:
    for path in (SERVICE, RUNNER, UNIT, ENV, README, WORKFLOW):
        if not path.is_file():
            raise SystemExit(
                f"missing required Wardveil Scan service file: {path.relative_to(ROOT)}"
            )

    service = SERVICE.read_text()
    runner = RUNNER.read_text()
    unit = UNIT.read_text()
    workflow = WORKFLOW.read_text()

    for token in (
        'LOOPBACK_HOST = "127.0.0.1"',
        "Authorization",
        "hmac.compare_digest",
        "application/octet-stream",
        "X-Wardveil-Resource-ID",
        "X-Wardveil-Digest-SHA256",
        "resource_digest_mismatch",
        "scan_result",
    ):
        require(service, token, "scan service")
    forbid(service, "0.0.0.0", "scan service")

    for token in (
        "WARDVEIL_SCAN_SERVICE_TOKEN",
        "WardveilScanService",
        "build_http_server",
    ):
        require(runner, token, "scan service runner")

    for token in (
        "DynamicUser=yes",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "IPAddressDeny=any",
        "IPAddressAllow=127.0.0.0/8",
        "/etc/goreecloud/wardveil/clamav.env",
        "/etc/goreecloud/wardveil/scan-service.env",
    ):
        require(unit, token, "systemd unit")
    forbid(unit, "0.0.0.0", "systemd unit")

    for token in (
        "scripts/test_wardveil_scan_service.py",
        "scripts/validate_wardveil_scan_service.py",
        "reference/wardveil_scan_service.py",
    ):
        require(workflow, token, "scan service validation workflow")

    print("Wardveil authenticated Scan service deployment contract valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
