#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import replace
from datetime import datetime, timezone
from uuid import uuid4

from reference.wardveil_scan_transport import ScanTransportRequest, sign_scan_request

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def load_caller() -> dict:
    payload = json.loads(os.environ.get("WARDVEIL_SCAN_CALLERS_JSON", "[]"))
    for item in payload:
        if item.get("active", True) and item.get("resource_types"):
            return item
    raise SystemExit("no active scan caller configured")


def scan(base_url: str, caller: dict, body: bytes, *, label: str) -> str:
    resource_type = str(caller["resource_types"][0])
    digest = hashlib.sha256(body).hexdigest()
    request = ScanTransportRequest(
        caller_id=str(caller["caller_id"]),
        key_id=str(caller["key_id"]),
        timestamp=datetime.now(timezone.utc).isoformat(),
        nonce=f"probe-{uuid4()}",
        action="runtime_acceptance_probe",
        resource_type=resource_type,
        resource_id=f"wardveil-probe:{resource_type}:{uuid4()}",
        correlation_id=f"probe-{uuid4()}",
        content_length=len(body),
        content_sha256=digest,
        signature="0" * 64,
    )
    request = replace(request, signature=sign_scan_request(request, str(caller["secret"]).encode("utf-8")))
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
        "X-Wardveil-Content-SHA256": request.content_sha256,
        "X-Wardveil-Signature": request.signature,
    }
    req = urllib.request.Request(base_url.rstrip("/") + "/v1/scan", data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            payload = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"{label} scan transport rejected request with HTTP {exc.code}") from exc
    record = payload.get("scan_record") or {}
    if payload.get("resource_digest_sha256") != digest:
        raise SystemExit(f"{label} scan returned digest mismatch")
    if record.get("scope", {}).get("resource_type") != resource_type:
        raise SystemExit(f"{label} scan returned scope mismatch")
    if record.get("producer", {}).get("authoritative") is not True:
        raise SystemExit(f"{label} scan did not return authoritative producer")
    return str(record.get("result", ""))


def main() -> None:
    base_url = os.environ.get("WARDVEIL_SCAN_PROBE_URL", "http://127.0.0.1:8788")
    caller = load_caller()
    clean = scan(base_url, caller, b"Wardveil authenticated clean control\n", label="clean")
    malicious = scan(base_url, caller, EICAR, label="EICAR")
    if clean != "clean":
        raise SystemExit(f"clean control expected clean, got {clean}")
    if malicious != "malicious":
        raise SystemExit(f"EICAR control expected malicious, got {malicious}")
    json.dump(
        {
            "component": "Wardveil Scan authenticated transport",
            "authenticated_transport": "passed",
            "clean_control": "passed",
            "eicar_detection": "passed",
            "direct_clamav_access": False,
            "production_runtime_acceptance": "unaccepted",
            "application_consumer_integration": "not_proven_by_probe",
        },
        sys.stdout,
        sort_keys=True,
    )
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
