#!/usr/bin/env python3
"""Exercise helpers used by the Wardveil Scan capacity acceptance harness."""

from __future__ import annotations

import importlib.util
import stat
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_scan_service import (  # noqa: E402
    DEFAULT_MAX_CONCURRENT_SCANS,
    CallerCredential,
)

MODULE_PATH = ROOT / "scripts" / "accept_wardveil_scan_capacity.py"
SPEC = importlib.util.spec_from_file_location("wardveil_scan_capacity_acceptance", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load Wardveil Scan capacity acceptance module")
capacity = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capacity)


def expect_exit(fn) -> None:
    try:
        fn()
    except SystemExit:
        return
    raise AssertionError("expected SystemExit")


def test_parse_process_environment() -> None:
    parsed = capacity.parse_process_environment(
        b"A=1\0WARDVEIL_SCAN_MAX_CONCURRENT_SCANS=3\0EMPTY=\0"
    )
    assert parsed == {
        "A": "1",
        "WARDVEIL_SCAN_MAX_CONCURRENT_SCANS": "3",
        "EMPTY": "",
    }
    expect_exit(lambda: capacity.parse_process_environment(b"missing-equals\0"))


def test_configured_concurrency_default_and_bounds() -> None:
    assert capacity.configured_max_concurrent_scans({}) == DEFAULT_MAX_CONCURRENT_SCANS
    assert capacity.configured_max_concurrent_scans(
        {"WARDVEIL_SCAN_MAX_CONCURRENT_SCANS": "1"}
    ) == 1
    assert capacity.configured_max_concurrent_scans(
        {"WARDVEIL_SCAN_MAX_CONCURRENT_SCANS": "8"}
    ) == 8
    expect_exit(
        lambda: capacity.configured_max_concurrent_scans(
            {"WARDVEIL_SCAN_MAX_CONCURRENT_SCANS": "0"}
        )
    )
    expect_exit(
        lambda: capacity.configured_max_concurrent_scans(
            {"WARDVEIL_SCAN_MAX_CONCURRENT_SCANS": "not-an-int"}
        )
    )
    expect_exit(
        lambda: capacity.configured_max_concurrent_scans(
            {
                "WARDVEIL_SCAN_MAX_CONCURRENT_SCANS": str(
                    capacity.MAX_ACCEPTANCE_SLOTS + 1
                )
            }
        )
    )


def test_header_only_request_is_authenticated_without_body() -> None:
    caller = CallerCredential(
        caller_id="goreecloud-drive",
        key_id="scan-current",
        secret=b"s" * 32,
        resource_types=frozenset({"drive_file"}),
        active=True,
    )
    request = capacity.signed_request(
        caller,
        capacity.CONTROL_BODY,
        resource_type="drive_file",
        phase="unit-hold",
    )
    wire = capacity.header_only_http_request(8791, request)
    assert wire.endswith(b"\r\n\r\n")
    assert f"Content-Length: {len(capacity.CONTROL_BODY)}\r\n".encode("ascii") in wire
    assert b"X-Wardveil-Caller-ID: goreecloud-drive\r\n" in wire
    assert b"X-Wardveil-Key-ID: scan-current\r\n" in wire
    assert b"X-Wardveil-Signature: " in wire
    assert capacity.CONTROL_BODY not in wire


def test_evidence_is_private_and_secret_free() -> None:
    secret = b"z" * 32
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "evidence.json"
        capacity.write_evidence(
            path,
            {
                "component": "unit capacity evidence",
                "capacity_concurrency_exhaustion": "passed",
                "caller_secret_in_evidence": False,
                "raw_resource_content_in_evidence": False,
                "production_runtime_acceptance": "unaccepted",
                "protection_claim_authority": False,
            },
            forbidden_secrets=(secret,),
        )
        raw = path.read_bytes()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert secret not in raw
        assert capacity.CONTROL_EVIDENCE_MARKER not in raw

        expect_exit(
            lambda: capacity.write_evidence(
                Path(directory) / "bad.json",
                {"leak": secret.decode("ascii")},
                forbidden_secrets=(secret,),
            )
        )


def main() -> int:
    tests = [
        value
        for name, value in sorted(globals().items())
        if name.startswith("test_") and callable(value)
    ]
    for test in tests:
        test()
    print(f"Wardveil Scan capacity acceptance helper tests passed ({len(tests)} cases).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
