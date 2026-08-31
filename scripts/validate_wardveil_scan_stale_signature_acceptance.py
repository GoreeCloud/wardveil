#!/usr/bin/env python3
"""Validate source wiring for stale ClamAV signature target acceptance."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "scripts" / "accept_wardveil_scan_stale_signature.py"
TEST = ROOT / "scripts" / "test_wardveil_scan_stale_signature_acceptance.py"
WORKFLOW = ROOT / ".github" / "workflows" / "validate-scan-service.yml"
RUNTIME = ROOT / "reference" / "wardveil_clamav_runtime.py"
SERVICE = ROOT / "reference" / "wardveil_scan_service.py"


def require(text: str, markers: tuple[str, ...], label: str) -> None:
    missing = [marker for marker in markers if marker not in text]
    if missing:
        raise SystemExit(f"{label} missing markers: {missing}")


def main() -> int:
    harness = HARNESS.read_text(encoding="utf-8")
    test = TEST.read_text(encoding="utf-8")
    workflow = WORKFLOW.read_text(encoding="utf-8")
    runtime = RUNTIME.read_text(encoding="utf-8")
    service = SERVICE.read_text(encoding="utf-8")

    require(
        runtime,
        (
            "DEFAULT_MAX_SIGNATURE_AGE_HOURS = 48.0",
            'freshness = "stale"',
            'reasons.append("signature_database_stale")',
            '"scanner_health_not_acceptable_for_clean_verdict"',
        ),
        "ClamAV runtime",
    )
    require(
        service,
        (
            "health = collect_clamav_health(",
            "finding = gate_clamav_verdict(",
            "now=observed_now",
        ),
        "Scan service",
    )
    require(
        harness,
        (
            "WardveilScanService(",
            'if stale_health.signature_freshness != "stale"',
            'if stale_clean["scan_record"]["result"] != "unknown"',
            'if stale_eicar["scan_record"]["result"] != "malicious"',
            'if recovery_clean["scan_record"]["result"] != "clean"',
            '"system_clock_changed": False',
            '"production_signature_database_modified": False',
            '"production_clamav_restarted": False',
            '"production_wardveil_scan_restarted": False',
            '"actual_production_signature_database_stale_event": "not_performed"',
            '"production_runtime_acceptance": "unaccepted"',
            '"protection_claim_authority": False',
            "os.O_EXCL",
            "0o600",
        ),
        "acceptance harness",
    )
    require(
        test,
        (
            'assert result["stale_clean"]["scan_record"]["result"] == "unknown"',
            'assert result["stale_eicar"]["scan_record"]["result"] == "malicious"',
            'assert result["recovery_clean"]["scan_record"]["result"] == "clean"',
        ),
        "acceptance regression",
    )
    require(
        workflow,
        (
            "scripts/accept_wardveil_scan_stale_signature.py",
            "scripts/test_wardveil_scan_stale_signature_acceptance.py",
            "scripts/validate_wardveil_scan_stale_signature_acceptance.py",
            "Test stale scanner signature acceptance helpers",
            "Validate stale scanner signature acceptance wiring",
        ),
        "Scan validation workflow",
    )

    print("Wardveil Scan stale-signature acceptance wiring validated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
