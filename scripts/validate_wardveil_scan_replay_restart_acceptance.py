#!/usr/bin/env python3
"""Validate the Wardveil Scan restart-survival acceptance command and deployment gate."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ACCEPT = ROOT / "scripts" / "accept_wardveil_scan_replay_restart.py"
TEST = ROOT / "scripts" / "test_wardveil_scan_replay_restart_acceptance.py"
DEPLOY = ROOT / ".github" / "workflows" / "deploy-scan-service-production.yml"
README = ROOT / "deployment" / "scan-service" / "README.md"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def require_tokens(text: str, tokens: tuple[str, ...], context: str) -> None:
    for token in tokens:
        require(token in text, f"{context} missing required token: {token}")


def main() -> int:
    for path in (ACCEPT, TEST, DEPLOY, README):
        require(path.is_file(), f"missing restart acceptance file: {path.relative_to(ROOT)}")

    accept = ACCEPT.read_text(encoding="utf-8")
    deploy = DEPLOY.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")

    require_tokens(
        accept,
        (
            "restart replay acceptance must run as root",
            "systemctl\", \"restart\", SERVICE_NAME",
            'systemctl_value("InvocationID")',
            "systemd invocation identity did not change",
            "exact replay after restart did not return the identical cached envelope",
            "conflicting same-nonce request after restart returned HTTP",
            "if conflict_status != 409",
            "SELECT expires_at_us, response_json FROM replay_entries",
            "Wardveil Scan replay database must be mode 0600",
            "Wardveil Scan replay state directory must be mode 0700",
            "caller secret would leak into restart acceptance evidence",
            "raw test content would leak into restart acceptance evidence",
            '"single_host_restart_durability": "passed"',
            '"multi_host_replay_durability": "not_proven"',
            '"production_runtime_acceptance": "unaccepted"',
            '"protection_claim_authority": False',
        ),
        "restart acceptance command",
    )

    require_tokens(
        deploy,
        (
            "reference/wardveil_scan_replay.py",
            "scripts/accept_wardveil_scan_replay_restart.py",
            "replay-restart",
            "single_host_restart_durability",
            "multi_host_replay_durability",
        ),
        "production deployment workflow",
    )

    require_tokens(
        readme,
        (
            "accept_wardveil_scan_replay_restart.py",
            "single-host restart durability",
            "multi-host",
        ),
        "Scan deployment README",
    )

    print("Wardveil Scan replay restart acceptance boundary valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
