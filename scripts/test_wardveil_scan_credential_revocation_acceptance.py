#!/usr/bin/env python3
"""Source tests for Wardveil Scan credential rotation/revocation acceptance helpers."""

from __future__ import annotations

import importlib.util
import json
import stat
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "accept_wardveil_scan_credential_revocation.py"
SPEC = importlib.util.spec_from_file_location("wardveil_scan_credential_revocation", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("unable to load credential revocation acceptance module")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)

from reference.wardveil_scan_service import CallerCredential, credentials_from_json  # noqa: E402


def expect_system_exit(callable_, message: str) -> None:
    try:
        callable_()
    except SystemExit:
        return
    raise AssertionError(message)


def main() -> int:
    original_entries = [
        {
            "caller_id": "goreecloud-drive",
            "key_id": "scan-current",
            "secret": "A" * 40,
            "resource_types": ["drive_file"],
            "active": True,
        }
    ]
    acceptance = CallerCredential(
        caller_id="wardveil-revocation-acceptance-test",
        key_id="pre-revoke",
        secret=b"B" * 40,
        resource_types=frozenset({"drive_file"}),
        active=True,
    )
    raw = module.registry_with_temporary_caller(original_entries, acceptance)
    payload = json.loads(raw)
    assert payload[:-1] == original_entries
    assert payload[-1]["caller_id"] == acceptance.caller_id
    assert payload[-1]["key_id"] == acceptance.key_id
    parsed = credentials_from_json(raw.decode("utf-8"))
    assert parsed[(acceptance.caller_id, acceptance.key_id)].active is True

    collision = CallerCredential(
        caller_id="goreecloud-drive",
        key_id="acceptance-collision",
        secret=b"C" * 40,
        resource_types=frozenset({"drive_file"}),
        active=True,
    )
    expect_system_exit(
        lambda: module.registry_with_temporary_caller(original_entries, collision),
        "existing caller collision must fail closed",
    )

    module.assert_rejected(401, {"error": "scan_request_rejected"})
    expect_system_exit(
        lambda: module.assert_rejected(403, {"error": "scan_request_rejected"}),
        "wrong rejection status must fail",
    )
    expect_system_exit(
        lambda: module.assert_rejected(401, {"error": "scan_signature_invalid"}),
        "specific authentication error must fail generic-envelope acceptance",
    )

    request = module.signed_request(acceptance, module.CONTROL_BODY, phase="unit")
    assert request.caller_id == acceptance.caller_id
    assert request.key_id == acceptance.key_id
    assert request.signature != "0" * 64
    assert len(request.signature) == 64

    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "evidence.json"
        evidence = {
            "revoked_credential_lifecycle": "passed",
            "caller_secret_in_evidence": False,
        }
        module.write_evidence(
            output,
            evidence,
            forbidden_secrets=(acceptance.secret, b"A" * 40),
        )
        assert json.loads(output.read_text(encoding="utf-8")) == evidence
        assert stat.S_IMODE(output.stat().st_mode) == 0o600

        expect_system_exit(
            lambda: module.write_evidence(
                output,
                {"leak": acceptance.secret.decode("ascii")},
                forbidden_secrets=(acceptance.secret,),
            ),
            "acceptance secret leakage must fail closed",
        )
        expect_system_exit(
            lambda: module.write_evidence(
                output,
                {"leak": module.CONTROL_BODY.decode("utf-8")},
                forbidden_secrets=(),
            ),
            "raw control-content leakage must fail closed",
        )

    print("Wardveil Scan credential revocation acceptance helper tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
