#!/usr/bin/env python3
"""Probe a deployed Wardveil Scan transport without claiming app integration."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_scan_service import (  # noqa: E402
    CallerCredential,
    ScanServiceRequest,
    credentials_from_json,
    sign_scan_request,
)

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def load_caller(path: Path) -> CallerCredential:
    credentials = credentials_from_json(path.read_text(encoding="utf-8"))
    for credential in credentials.values():
        if credential.active and credential.resource_types:
            return credential
    raise SystemExit("no active Wardveil Scan caller credential is available for the probe")


def signed_request(caller: CallerCredential, body: bytes, *, label: str) -> ScanServiceRequest:
    resource_type = sorted(caller.resource_types)[0]
    request = ScanServiceRequest(
        caller_id=caller.caller_id,
        key_id=caller.key_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        nonce=f"probe-{uuid4()}",
        action="runtime_acceptance_probe",
        resource_type=resource_type,
        resource_id=f"wardveil-probe:{resource_type}:{label}:{uuid4()}",
        digest_sha256=hashlib.sha256(body).hexdigest(),
        size_bytes=len(body),
        correlation_id=f"probe-{uuid4()}",
        signature="0" * 64,
    )
    return replace(
        request,
        signature=sign_scan_request(request, caller.secret),
    )


def scan(base_url: str, caller: CallerCredential, body: bytes, *, label: str) -> str:
    request = signed_request(caller, body, label=label)
    headers = {
        "Content-Type": "application/octet-stream",
        "X-Wardveil-Caller-ID": request.caller_id,
        "X-Wardveil-Key-ID": request.key_id,
        "X-Wardveil-Timestamp": request.timestamp,
        "X-Wardveil-Nonce": request.nonce,
        "X-Wardveil-Action": request.action,
        "X-Wardveil-Resource-Type": request.resource_type,
        "X-Wardveil-Resource-ID": request.resource_id,
        "X-Wardveil-Correlation-ID": request.correlation_id,
        "X-Wardveil-Digest-SHA256": request.digest_sha256,
        "X-Wardveil-Size-Bytes": str(request.size_bytes),
        "X-Wardveil-Signature": request.signature,
    }
    http_request = urllib.request.Request(
        base_url.rstrip("/") + "/v1/scan",
        data=body,
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(http_request, timeout=20) as response:
            if response.status != 200:
                raise SystemExit(f"{label} scan returned unexpected HTTP {response.status}")
            payload = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        raise SystemExit(
            f"{label} Wardveil Scan request was rejected with HTTP {exc.code}"
        ) from exc

    record = payload.get("scan_record") or {}
    if payload.get("resource_id") != request.resource_id:
        raise SystemExit(f"{label} scan returned resource identity mismatch")
    if payload.get("resource_digest_sha256") != request.digest_sha256:
        raise SystemExit(f"{label} scan returned digest mismatch")
    if record.get("record_type") != "scan_finding":
        raise SystemExit(f"{label} scan returned unexpected record type")
    if "scan_result" in record or "result" not in record:
        raise SystemExit(f"{label} scan returned incompatible consumer result field")
    if record.get("scope") != {
        "resource_type": request.resource_type,
        "resource_id": request.resource_id,
    }:
        raise SystemExit(f"{label} scan returned scope mismatch")
    if record.get("producer", {}).get("authoritative") is not True:
        raise SystemExit(f"{label} scan did not return an authoritative producer")
    if not record.get("evidence_refs"):
        raise SystemExit(f"{label} scan returned no evidence references")
    encoded = json.dumps(payload, sort_keys=True)
    if body.decode("ascii", errors="ignore") in encoded:
        raise SystemExit(f"{label} raw resource content leaked into response")
    return str(record.get("result", ""))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--url",
        default=os.environ.get("WARDVEIL_SCAN_PROBE_URL", "http://127.0.0.1:8791"),
    )
    parser.add_argument(
        "--callers-file",
        default=os.environ.get("WARDVEIL_SCAN_CALLERS_FILE", ""),
    )
    args = parser.parse_args()

    if args.url != "http://127.0.0.1:8791":
        raise SystemExit("runtime probe currently accepts only the loopback Wardveil Scan URL")
    if not args.callers_file:
        raise SystemExit("--callers-file is required")
    caller = load_caller(Path(args.callers_file))

    clean = scan(args.url, caller, b"Wardveil authenticated clean control\n", label="clean")
    malicious = scan(args.url, caller, EICAR, label="eicar")
    if clean != "clean":
        raise SystemExit(f"clean control expected clean, got {clean}")
    if malicious != "malicious":
        raise SystemExit(f"EICAR control expected malicious, got {malicious}")

    json.dump(
        {
            "component": "Wardveil Scan authenticated transport",
            "authenticated_transport": "passed",
            "consumer_envelope_compatibility": "passed",
            "clean_control": "passed",
            "eicar_detection": "passed",
            "direct_clamav_access": False,
            "application_consumer_integration": "not_proven_by_probe",
            "production_service_identity": "not_proven_by_probe",
            "quarantine_execution": "not_proven_by_probe",
            "production_runtime_acceptance": "unaccepted",
        },
        sys.stdout,
        sort_keys=True,
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
