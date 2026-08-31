#!/usr/bin/env python3
"""Prove bounded authenticated Wardveil Scan concurrency exhaustion and recovery."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_scan_service import (  # noqa: E402
    DEFAULT_MAX_CONCURRENT_SCANS,
    CallerCredential,
    ScanServiceRequest,
    credentials_from_json,
    sign_scan_request,
)

LOOPBACK_URL = "http://127.0.0.1:8791"
SERVICE_NAME = "wardveil-scan.service"
CONTROL_BODY = b"Wardveil Scan capacity acceptance clean control\n"
CONTROL_EVIDENCE_MARKER = CONTROL_BODY.rstrip()
HTTP_TIMEOUT_SECONDS = 10
MAX_HTTP_RESPONSE_BYTES = 1 << 20
ALLOWED_REGISTRY_MODES = {0o400, 0o600}
MAX_ACCEPTANCE_SLOTS = 32
BUSY_ATTEMPTS = 20
RECOVERY_ATTEMPTS = 30


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def read_http_json(response) -> dict:
    raw = response.read(MAX_HTTP_RESPONSE_BYTES + 1)
    if len(raw) > MAX_HTTP_RESPONSE_BYTES:
        fail("Wardveil Scan response exceeds the acceptance bound")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit("Wardveil Scan returned invalid JSON") from exc
    if not isinstance(payload, dict):
        fail("Wardveil Scan returned a non-object JSON response")
    return payload


def request_headers(request: ScanServiceRequest) -> dict[str, str]:
    return {
        "Content-Type": "application/octet-stream",
        "X-Wardveil-Caller-ID": request.caller_id,
        "X-Wardveil-Key-ID": request.key_id,
        "X-Wardveil-Timestamp": request.timestamp,
        "X-Wardveil-Nonce": request.nonce,
        "X-Wardveil-Resource-Type": request.resource_type,
        "X-Wardveil-Resource-ID": request.resource_id,
        "X-Wardveil-Digest-SHA256": request.digest_sha256,
        "X-Wardveil-Size-Bytes": str(request.size_bytes),
        "X-Wardveil-Action": request.action,
        "X-Wardveil-Correlation-ID": request.correlation_id,
        "X-Wardveil-Signature": request.signature,
    }


def signed_request(
    caller: CallerCredential,
    body: bytes,
    *,
    resource_type: str,
    phase: str,
) -> ScanServiceRequest:
    request = ScanServiceRequest(
        caller_id=caller.caller_id,
        key_id=caller.key_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        nonce=f"capacity-{phase}-{uuid4()}",
        action="runtime_capacity_probe",
        resource_type=resource_type,
        resource_id=f"wardveil-capacity-{phase}:{uuid4()}",
        digest_sha256=hashlib.sha256(body).hexdigest(),
        size_bytes=len(body),
        correlation_id=f"capacity-{phase}-{uuid4()}",
        signature="0" * 64,
    )
    return replace(request, signature=sign_scan_request(request, caller.secret))


def post_scan(url: str, request: ScanServiceRequest, body: bytes) -> tuple[int, dict]:
    http_request = urllib.request.Request(
        url.rstrip("/") + "/v1/scan",
        data=body,
        headers=request_headers(request),
        method="POST",
    )
    try:
        with urllib.request.urlopen(http_request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            return response.status, read_http_json(response)
    except urllib.error.HTTPError as exc:
        return exc.code, read_http_json(exc)
    except urllib.error.URLError as exc:
        raise SystemExit(f"Wardveil Scan request transport failed: {exc.reason}") from exc


def assert_clean(status: int, payload: dict, request: ScanServiceRequest) -> None:
    if status != 200:
        fail(f"expected accepted clean Wardveil Scan request, got HTTP {status}")
    record = payload.get("scan_record")
    if not isinstance(record, dict) or record.get("result") != "clean":
        fail("capacity acceptance clean control did not return a clean finding")
    if payload.get("resource_id") != request.resource_id:
        fail("capacity acceptance clean control returned the wrong resource identity")
    if payload.get("resource_digest_sha256") != request.digest_sha256:
        fail("capacity acceptance clean control returned the wrong digest")


def health(url: str) -> dict:
    try:
        with urllib.request.urlopen(url.rstrip("/") + "/healthz", timeout=3) as response:
            if response.status != 200:
                fail(f"Wardveil Scan health returned HTTP {response.status}")
            payload = read_http_json(response)
    except urllib.error.URLError as exc:
        raise SystemExit(f"Wardveil Scan health transport failed: {exc.reason}") from exc
    if payload.get("status") != "ok":
        fail("Wardveil Scan health did not return ok")
    if payload.get("component") != "Wardveil Scan authenticated transport":
        fail("Wardveil Scan health component mismatch")
    if payload.get("production_runtime_status") != "unaccepted":
        fail("Wardveil Scan health unexpectedly claims production runtime acceptance")
    if payload.get("protection_claim_authority") is not False:
        fail("Wardveil Scan health unexpectedly grants protection claim authority")
    return payload


def systemctl_value(service: str, property_name: str) -> str:
    result = subprocess.run(
        ["systemctl", "show", service, f"--property={property_name}", "--value"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout.strip()


def service_active(service: str) -> bool:
    result = subprocess.run(
        ["systemctl", "is-active", "--quiet", service],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def parse_process_environment(raw: bytes) -> dict[str, str]:
    environment: dict[str, str] = {}
    for item in raw.split(b"\0"):
        if not item:
            continue
        if b"=" not in item:
            fail("Wardveil Scan process environment contains a malformed entry")
        key, value = item.split(b"=", 1)
        try:
            name = key.decode("utf-8")
            text = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SystemExit("Wardveil Scan process environment is not UTF-8") from exc
        environment[name] = text
    return environment


def running_process_environment(service: str) -> tuple[int, dict[str, str]]:
    main_pid_text = systemctl_value(service, "MainPID")
    if not main_pid_text.isdigit() or int(main_pid_text) < 2:
        fail("Wardveil Scan service does not expose a live MainPID")
    main_pid = int(main_pid_text)
    environment_path = Path(f"/proc/{main_pid}/environ")
    try:
        raw = environment_path.read_bytes()
    except OSError as exc:
        raise SystemExit(f"cannot read Wardveil Scan process environment: {exc}") from exc
    return main_pid, parse_process_environment(raw)


def configured_max_concurrent_scans(environment: dict[str, str]) -> int:
    configured = environment.get("WARDVEIL_SCAN_MAX_CONCURRENT_SCANS", "").strip()
    if configured:
        try:
            value = int(configured)
        except ValueError as exc:
            raise SystemExit("WARDVEIL_SCAN_MAX_CONCURRENT_SCANS is not an integer") from exc
    else:
        value = DEFAULT_MAX_CONCURRENT_SCANS
    if value < 1:
        fail("configured Wardveil Scan concurrency must be positive")
    if value > MAX_ACCEPTANCE_SLOTS:
        fail(
            "configured Wardveil Scan concurrency exceeds the bounded acceptance harness limit "
            f"of {MAX_ACCEPTANCE_SLOTS}"
        )
    return value


def load_caller(
    path: Path,
    *,
    caller_id: str,
    key_id: str,
    resource_type: str,
) -> tuple[CallerCredential, tuple[bytes, ...]]:
    if not path.is_absolute():
        fail("Wardveil Scan caller credential path must be absolute")
    if path.is_symlink() or not path.is_file():
        fail("Wardveil Scan caller credential path must be a regular non-symlink file")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode not in ALLOWED_REGISTRY_MODES:
        fail("Wardveil Scan caller credential file must be mode 0400 or 0600")
    credentials = credentials_from_json(path.read_text(encoding="utf-8"))
    caller = credentials.get((caller_id, key_id))
    if caller is None or not caller.active:
        fail("selected Wardveil Scan capacity caller is missing or inactive")
    if resource_type not in caller.resource_types:
        fail("selected Wardveil Scan capacity caller lacks the requested resource scope")
    return caller, tuple(item.secret for item in credentials.values())


def header_only_http_request(port: int, request: ScanServiceRequest) -> bytes:
    lines = [
        "POST /v1/scan HTTP/1.1",
        f"Host: 127.0.0.1:{port}",
        "Content-Type: application/octet-stream",
        f"Content-Length: {request.size_bytes}",
    ]
    lines.extend(f"{name}: {value}" for name, value in request_headers(request).items() if name != "Content-Type")
    lines.extend(("Connection: close", "", ""))
    return "\r\n".join(lines).encode("ascii")


def open_held_authenticated_request(port: int, request: ScanServiceRequest) -> socket.socket:
    client = socket.create_connection(("127.0.0.1", port), timeout=2)
    client.settimeout(2)
    try:
        client.sendall(header_only_http_request(port, request))
    except Exception:
        client.close()
        raise
    return client


def close_held_requests(clients: list[socket.socket]) -> None:
    for client in clients:
        try:
            client.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            client.close()
        except OSError:
            pass


def write_evidence(path: Path, evidence: dict, *, forbidden_secrets: tuple[bytes, ...]) -> None:
    if not path.is_absolute():
        fail("capacity acceptance evidence path must be absolute")
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(evidence, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    if CONTROL_EVIDENCE_MARKER in raw:
        fail("raw control content would leak into capacity acceptance evidence")
    for secret in forbidden_secrets:
        if secret and secret in raw:
            fail("caller secret would leak into capacity acceptance evidence")
    fd, temporary = tempfile.mkstemp(prefix=".wardveil-capacity-evidence-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=LOOPBACK_URL)
    parser.add_argument("--service", default=SERVICE_NAME)
    parser.add_argument("--callers-file", required=True)
    parser.add_argument("--caller-id", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--resource-type", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    if os.geteuid() != 0:
        fail("capacity acceptance must run as root")
    if args.url != LOOPBACK_URL:
        fail("capacity acceptance accepts only the loopback Wardveil Scan URL")
    if args.service != SERVICE_NAME:
        fail("capacity acceptance accepts only wardveil-scan.service")
    if (
        len(args.source_revision) != 40
        or any(ch not in "0123456789abcdef" for ch in args.source_revision)
    ):
        fail("--source-revision must be an exact lowercase 40-character Git SHA")

    if not service_active(args.service):
        fail("Wardveil Scan service is not active before capacity acceptance")
    initial_invocation = systemctl_value(args.service, "InvocationID")
    if not initial_invocation:
        fail("Wardveil Scan service has no InvocationID before capacity acceptance")
    health(args.url)

    caller, forbidden_secrets = load_caller(
        Path(args.callers_file),
        caller_id=args.caller_id,
        key_id=args.key_id,
        resource_type=args.resource_type,
    )
    main_pid, environment = running_process_environment(args.service)
    max_concurrent_scans = configured_max_concurrent_scans(environment)

    held_clients: list[socket.socket] = []
    pre_busy_clean_attempts = 0
    busy_attempt = 0
    try:
        for index in range(max_concurrent_scans):
            request = signed_request(
                caller,
                CONTROL_BODY,
                resource_type=args.resource_type,
                phase=f"hold-{index + 1}",
            )
            held_clients.append(open_held_authenticated_request(8791, request))

        # Give the ThreadingHTTPServer handlers a bounded moment to authenticate and
        # block on their declared request bodies while holding the scan semaphore.
        time.sleep(0.35)

        for attempt in range(1, BUSY_ATTEMPTS + 1):
            overflow = signed_request(
                caller,
                CONTROL_BODY,
                resource_type=args.resource_type,
                phase=f"overflow-{attempt}",
            )
            status, payload = post_scan(args.url, overflow, CONTROL_BODY)
            if status == 503:
                if payload != {"error": "scan_service_busy"}:
                    fail("capacity exhaustion did not return the bounded busy envelope")
                busy_attempt = attempt
                break
            if status == 200:
                assert_clean(status, payload, overflow)
                pre_busy_clean_attempts += 1
                time.sleep(0.05)
                continue
            fail(f"unexpected HTTP {status} while proving Scan capacity exhaustion")
        else:
            fail("configured Wardveil Scan concurrency could not be driven to scan_service_busy")
    finally:
        close_held_requests(held_clients)

    recovery_attempt = 0
    for attempt in range(1, RECOVERY_ATTEMPTS + 1):
        recovery = signed_request(
            caller,
            CONTROL_BODY,
            resource_type=args.resource_type,
            phase=f"recovery-{attempt}",
        )
        status, payload = post_scan(args.url, recovery, CONTROL_BODY)
        if status == 200:
            assert_clean(status, payload, recovery)
            recovery_attempt = attempt
            break
        if status == 503 and payload == {"error": "scan_service_busy"}:
            time.sleep(0.1)
            continue
        fail(f"unexpected HTTP {status} while waiting for Scan capacity recovery")
    else:
        fail("Wardveil Scan did not recover after releasing capacity acceptance requests")

    post_health = health(args.url)
    if not service_active(args.service):
        fail("Wardveil Scan service is not active after capacity acceptance")
    final_invocation = systemctl_value(args.service, "InvocationID")
    if final_invocation != initial_invocation:
        fail("Wardveil Scan restarted unexpectedly during capacity acceptance")

    evidence = {
        "component": "Wardveil Scan bounded concurrency capacity acceptance",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "wardveil_revision": args.source_revision,
        "wardveil_endpoint": args.url.rstrip("/") + "/v1/scan",
        "service": args.service,
        "service_main_pid": main_pid,
        "caller_id": args.caller_id,
        "key_id": args.key_id,
        "resource_type": args.resource_type,
        "configured_max_concurrent_scans": max_concurrent_scans,
        "held_authenticated_requests": len(held_clients),
        "busy_http_status": 503,
        "busy_error_code": "scan_service_busy",
        "busy_response": "passed",
        "overflow_attempts_before_busy": busy_attempt,
        "pre_busy_clean_attempts": pre_busy_clean_attempts,
        "held_requests_released": True,
        "recovery_clean_request": "passed",
        "recovery_attempt": recovery_attempt,
        "post_acceptance_health": "passed",
        "post_acceptance_health_runtime_status": post_health["production_runtime_status"],
        "service_restart_performed": False,
        "wardveil_invocation_unchanged": True,
        "capacity_concurrency_exhaustion": "passed",
        "raw_resource_content_in_evidence": False,
        "caller_secret_in_evidence": False,
        "production_service_identity": "not_proven_by_acceptance",
        "multi_host_capacity_behavior": "not_proven",
        "production_runtime_acceptance": "unaccepted",
        "protection_claim_authority": False,
    }
    write_evidence(Path(args.output), evidence, forbidden_secrets=forbidden_secrets)
    print(json.dumps(evidence, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
