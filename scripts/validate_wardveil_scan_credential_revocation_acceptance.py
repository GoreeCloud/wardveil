#!/usr/bin/env python3
"""Validate source/deployment wiring for Wardveil Scan credential revocation acceptance."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ACCEPTANCE = ROOT / "scripts" / "accept_wardveil_scan_credential_revocation.py"
WORKFLOW = ROOT / ".github" / "workflows" / "deploy-scan-service-production.yml"
VALIDATION_WORKFLOW = ROOT / ".github" / "workflows" / "validate-scan-service.yml"


def require(text: str, marker: str, context: str) -> None:
    if marker not in text:
        raise SystemExit(f"missing {context}: {marker}")


def main() -> int:
    acceptance = ACCEPTANCE.read_text(encoding="utf-8")
    deployment = WORKFLOW.read_text(encoding="utf-8")
    validation = VALIDATION_WORKFLOW.read_text(encoding="utf-8")

    for marker in (
        "temporary acceptance-only caller",
        "ALLOWED_REGISTRY_MODES = {0o400, 0o600}",
        "atomic_replace(",
        "original_raw",
        "finally:",
        '"old_credential_after_rotation": "rejected"',
        '"replacement_credential_after_rotation": "passed"',
        '"replacement_credential_after_explicit_revocation": "rejected"',
        '"original_credential_registry_restored": True',
        '"revoked_credential_lifecycle": "passed"',
        '"caller_secret_in_evidence": False',
        '"production_runtime_acceptance": "unaccepted"',
        'payload != {"error": "scan_request_rejected"}',
    ):
        require(acceptance, marker, "credential acceptance safety marker")

    for marker in (
        "scripts/accept_wardveil_scan_credential_revocation.py",
        'revocation_evidence="$base/evidence/$revision-credential-revocation.json"',
        'python3 "$release/scripts/accept_wardveil_scan_credential_revocation.py"',
        '--callers-file "$callers"',
        '--source-revision "$revision"',
        '--output "$revocation_evidence"',
        '"revoked_credential_lifecycle"',
        '"old_credential_after_rotation"',
        '"replacement_credential_after_explicit_revocation"',
        '"original_credential_registry_restored"',
        '"production_runtime_acceptance"',
    ):
        require(deployment, marker, "production deployment acceptance wiring")

    for marker in (
        "scripts/accept_wardveil_scan_credential_revocation.py",
        "scripts/test_wardveil_scan_credential_revocation_acceptance.py",
        "scripts/validate_wardveil_scan_credential_revocation_acceptance.py",
        "Test credential revocation acceptance helpers",
        "Validate credential revocation acceptance wiring",
    ):
        require(validation, marker, "source validation workflow wiring")

    print("Wardveil Scan credential revocation acceptance wiring validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
