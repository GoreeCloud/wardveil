#!/usr/bin/env python3
"""Prove same-host Wardveil Scan replay state survives a real service restart."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import asdict, replace
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

LOOPBACK_URL = "http://127.0.0.1:8791"
SERVICE_NAME = "wardveil-scan.service"
DEFAULT_REPLAY_DB = Path("/var/lib/wardveil-scan/replay.sqlite3")
CONTROL_BODY = b"Wardveil durable replay restart acceptance control\n"
CONFLICT_BODY = b"Wardveil durable replay restart conflicting control\n"
MAX_REPLAY_AGE_SECONDS = 50.0
HTTP_TIMEOUT_SECONDS = 10
HEALTH_TIMEOUT_SECONDS = 20.0
MAX_HTTP_RESPONSE_BYTES = 1 << 20


def fail(message: str) -> "NoReturn":
    raise SystemExit(message)


def canonical_json_bytes(payload: dict) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def sha256_json(payload: dict) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def load_caller(
    path: Path,
    *,
    caller_id: str,
    key_id: str,
    resource_type: str,
) -> CallerCredential:
    if path.is_symlink() or not path.is_file():
        fail("Wardveil Scan caller credential path must be a regular non-symlink file")
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        fail("Wardveil Scan caller credential file must be owner-only")
    credentials = credentials_from_json(path.read_text(encoding="utf-8"))
    caller = credentials.get((caller_id, key_id))
    if caller is None or not caller.active:
        fail("requested Wardveil Scan caller/key is unavailable or inactive")
    if resource_type not in caller.resource_types:
        fail("requested Wardveil Scan caller/key lacks the required resource scope")
    return caller


def signed_request(caller: CallerCredential, body: bytes) -> ScanServiceRequest:
    request = ScanServiceRequest(
        caller_id=caller.caller_id,
        key_id=caller.key_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        nonce=f"restart-acceptance-{uuid4()}",
        action="runtime_acceptance_probe",
        resource_type="drive_file",
        resource_id=f"wardveil-replay-restart:drive_file:{uuid4()}",
        digest_sha256=hashlib.sha256(body).hexdigest(),
        size_bytes=len(body),
        correlation_id=f"restart-acceptance-{uuid4()}",
        signature="0" * 64,
    )
    return replace(request, signature=sign_scan_request(request, caller.secret))


def request_headers(request: ScanServiceRequest) -> dict[str, str]:
    return {
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


def validate_clean_envelope(
    payload: dict,
    request: ScanServiceRequest,
    *,
    body: bytes,
) -> None:
    record = payload.get("scan_record")
    if not isinstance(record, dict):
        fail("Wardveil Scan response is missing scan_record")
    if payload.get("resource_id") != request.resource_id:
        fail("Wardveil Scan replay acceptance resource identity mismatch")
    if payload.get("resource_digest_sha256") != request.digest_sha256:
        fail("Wardveil Scan replay acceptance digest mismatch")
    if record.get("record_type") != "scan_finding":
        fail("Wardveil Scan replay acceptance record type mismatch")
    if record.get("result") != "clean":
        fail(f"Wardveil Scan replay acceptance expected clean, got {record.get('result')}")
    if record.get("scope") != {
        "resource_type": request.resource_type,
        "resource_id": request.resource_id,
    }:
        fail("Wardveil Scan replay acceptance scope mismatch")
    if record.get("producer", {}).get("authoritative") is not True:
        fail("Wardveil Scan replay acceptance producer is not authoritative")
    if not record.get("evidence_refs"):
        fail("Wardveil Scan replay acceptance lacks evidence references")
    encoded = canonical_json_bytes(payload)
    if body in encoded:
        fail("raw acceptance content leaked into Wardveil Scan response")


def systemctl_value(property_name: str) -> str:
    result = subprocess.run(
        ["systemctl", "show", SERVICE_NAME, f"--property={property_name}", "--value"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout.strip()


def service_active() -> bool:
    result = subprocess.run(
        ["systemctl", "is-active", "--quiet", SERVICE_NAME],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def health(url: str) -> dict:
    with urllib.request.urlopen(url.rstrip("/") + "/healthz", timeout=3) as response:
        if response.status != 200:
            fail(f"Wardveil Scan health returned HTTP {response.status}")
        payload = read_http_json(response)
    if payload.get("status") != "ok":
        fail("Wardveil Scan health did not return ok")
    if payload.get("component") != "Wardveil Scan authenticated transport":
        fail("Wardveil Scan health component mismatch")
    if payload.get("production_runtime_status") != "unaccepted":
        fail("Wardveil Scan health unexpectedly claims production acceptance")
    if payload.get("protection_claim_authority") is not False:
        fail("Wardveil Scan health unexpectedly grants protection claim authority")
    return payload


def restart_service_and_wait(url: str) -> tuple[str, str, int, int]:
    before_invocation = systemctl_value("InvocationID")
    before_pid_raw = systemctl_value("MainPID")
    before_pid = int(before_pid_raw or "0")
    if not before_invocation or before_pid <= 0 or not service_active():
        fail("Wardveil Scan service is not active before restart acceptance")

    subprocess.run(["systemctl", "restart", SERVICE_NAME], check=True)

    deadline = time.monotonic() + HEALTH_TIMEOUT_SECONDS
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if service_active():
            try:
                health(url)
                break
            except Exception as exc:  # noqa: BLE001 - surfaced after bounded polling
                last_error = exc
        time.sleep(0.2)
    else:
        if last_error is not None:
            raise SystemExit(f"Wardveil Scan did not recover healthy after restart: {last_error}")
        fail("Wardveil Scan did not recover healthy after restart")

    after_invocation = systemctl_value("InvocationID")
    after_pid_raw = systemctl_value("MainPID")
    after_pid = int(after_pid_raw or "0")
    if not after_invocation or after_invocation == before_invocation:
        fail("systemd invocation identity did not change across Wardveil Scan restart")
    if after_pid <= 0:
        fail("Wardveil Scan has no active MainPID after restart")
    return before_invocation, after_invocation, before_pid, after_pid


def private_state_file() -> tuple[int, Path]:
    directory = Path("/run") if Path("/run").is_dir() else Path("/tmp")
    fd, name = tempfile.mkstemp(
        prefix="wardveil-scan-replay-restart-acceptance-",
        suffix=".json",
        dir=directory,
    )
    os.fchmod(fd, 0o600)
    return fd, Path(name)


def write_state(fd: int, path: Path, payload: dict, *, secret: str) -> None:
    raw = json.dumps(payload, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    if secret.encode("utf-8") in raw:
        fail("caller secret would leak into replay acceptance state")
    if CONTROL_BODY in raw or CONFLICT_BODY in raw:
        fail("raw test content would leak into replay acceptance state")
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(path, 0o600)


def read_state(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        fail("replay acceptance state is not a regular non-symlink file")
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        fail("replay acceptance state is not mode 0600")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        fail("replay acceptance state is invalid")
    return payload


def request_from_state(payload: dict) -> ScanServiceRequest:
    raw = payload.get("request")
    if not isinstance(raw, dict):
        fail("replay acceptance state lacks request metadata")
    return ScanServiceRequest(**raw)


def validate_replay_database(path: Path, request: ScanServiceRequest, expected: dict) -> None:
    if path.is_symlink() or not path.is_file():
        fail("Wardveil Scan replay database must be a regular non-symlink file")
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        fail("Wardveil Scan replay database must be mode 0600")
    parent_mode = stat.S_IMODE(path.parent.stat().st_mode)
    if parent_mode != 0o700:
        fail(f"Wardveil Scan replay state directory must be mode 0700, got {parent_mode:o}")

    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        row = connection.execute(
            "SELECT expires_at_us, response_json FROM replay_entries "
            "WHERE caller_id = ? AND key_id = ? AND nonce = ?",
            (request.caller_id, request.key_id, request.nonce),
        ).fetchone()
    finally:
        connection.close()
    if row is None:
        fail("durable replay database does not contain the accepted nonce")
    expires_at_us, response_json = row
    if int(expires_at_us) <= int(datetime.now(timezone.utc).timestamp() * 1_000_000):
        fail("durable replay acceptance row expired before verification")
    try:
        cached = json.loads(response_json)
    except (TypeError, json.JSONDecodeError) as exc:
        raise SystemExit("durable replay database cached response is invalid") from exc
    if cached != expected:
        fail("durable replay database cached envelope differs from first response")


def write_evidence(path: Path, evidence: dict, *, secret: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(evidence, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    if secret.encode("utf-8") in raw:
        fail("caller secret would leak into restart acceptance evidence")
    if CONTROL_BODY in raw or CONFLICT_BODY in raw:
        fail("raw test content would leak into restart acceptance evidence")
    fd, temporary = tempfile.mkstemp(prefix=".wardveil-restart-evidence-", dir=path.parent)
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
    parser.add_argument("--caller-id", default="goreecloud-drive")
    parser.add_argument("--key-id", default="scan-current")
    parser.add_argument("--resource-type", default="drive_file")
    parser.add_argument("--replay-db", default=str(DEFAULT_REPLAY_DB))
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    if os.geteuid() != 0:
        fail("restart replay acceptance must run as root")
    if args.url != LOOPBACK_URL:
        fail("restart replay acceptance accepts only the loopback Wardveil Scan URL")
    if args.service != SERVICE_NAME:
        fail("restart replay acceptance accepts only wardveil-scan.service")
    if not args.source_revision or any(ch not in "0123456789abcdef" for ch in args.source_revision) or len(args.source_revision) != 40:
        fail("--source-revision must be an exact lowercase 40-character Git SHA")

    caller = load_caller(
        Path(args.callers_file),
        caller_id=args.caller_id,
        key_id=args.key_id,
        resource_type=args.resource_type,
    )
    replay_db = Path(args.replay_db)
    output = Path(args.output)
    request = signed_request(caller, CONTROL_BODY)

    state_fd, state_path = private_state_file()
    state_removed = False
    try:
        first_status, first = post_scan(args.url, request, CONTROL_BODY)
        if first_status != 200:
            fail(f"initial restart acceptance request returned HTTP {first_status}")
        validate_clean_envelope(first, request, body=CONTROL_BODY)
        validate_replay_database(replay_db, request, first)

        state = {
            "schema": 1,
            "source_revision": args.source_revision,
            "prepared_at": datetime.now(timezone.utc).isoformat(),
            "request": asdict(request),
            "first_response": first,
            "first_response_sha256": sha256_json(first),
        }
        write_state(state_fd, state_path, state, secret=caller.secret)
        state_fd = -1

        before_invocation, after_invocation, before_pid, after_pid = restart_service_and_wait(args.url)

        persisted = read_state(state_path)
        if persisted.get("source_revision") != args.source_revision:
            fail("replay acceptance state source revision changed unexpectedly")
        replay_request = request_from_state(persisted)
        expected_signature = sign_scan_request(replay_request, caller.secret)
        if not hmac.compare_digest(expected_signature, replay_request.signature):
            fail("replay acceptance request signature no longer matches the active caller credential")
        signed_at = datetime.fromisoformat(replay_request.timestamp)
        age = (datetime.now(timezone.utc) - signed_at.astimezone(timezone.utc)).total_seconds()
        if age < -2 or age > MAX_REPLAY_AGE_SECONDS:
            fail(f"restart acceptance exceeded authenticated replay timing window: {age:.3f}s")

        second_status, second = post_scan(args.url, replay_request, CONTROL_BODY)
        if second_status != 200:
            fail(f"exact replay after restart returned HTTP {second_status}")
        validate_clean_envelope(second, replay_request, body=CONTROL_BODY)
        if second != persisted.get("first_response"):
            fail("exact replay after restart did not return the identical cached envelope")
        if sha256_json(second) != persisted.get("first_response_sha256"):
            fail("exact replay after restart response hash changed")

        validate_replay_database(replay_db, replay_request, second)

        conflict = replace(
            replay_request,
            digest_sha256=hashlib.sha256(CONFLICT_BODY).hexdigest(),
            size_bytes=len(CONFLICT_BODY),
            signature="0" * 64,
        )
        conflict = replace(
            conflict,
            signature=sign_scan_request(conflict, caller.secret),
        )
        conflict_status, conflict_payload = post_scan(args.url, conflict, CONFLICT_BODY)
        if conflict_status != 409:
            fail(f"conflicting same-nonce request after restart returned HTTP {conflict_status}")
        if conflict_payload.get("error") != "scan_request_rejected":
            fail("conflicting replay rejection returned unexpected response shape")

        state_path.unlink()
        state_removed = True

        evidence = {
            "component": "Wardveil Scan durable same-host replay restart acceptance",
            "wardveil_revision": args.source_revision,
            "wardveil_endpoint": args.url + "/v1/scan",
            "service": SERVICE_NAME,
            "caller_id": replay_request.caller_id,
            "key_id": replay_request.key_id,
            "resource_type": replay_request.resource_type,
            "initial_authenticated_clean_request": "passed",
            "service_restart": "passed",
            "systemd_invocation_changed": True,
            "main_pid_changed": before_pid != after_pid,
            "exact_replay_after_restart": "passed",
            "cached_envelope_identical": True,
            "conflicting_replay_after_restart": "passed",
            "replay_database": str(replay_db),
            "replay_database_mode": "0600",
            "replay_state_directory_mode": "0700",
            "transient_request_state_private": True,
            "transient_request_state_removed": state_removed,
            "raw_resource_content_in_evidence": False,
            "caller_secret_in_evidence": False,
            "single_host_restart_durability": "passed",
            "multi_host_replay_durability": "not_proven",
            "production_service_identity": "not_proven_by_acceptance",
            "production_runtime_acceptance": "unaccepted",
            "protection_claim_authority": False,
            "observed_at": datetime.now(timezone.utc).isoformat(),
        }
        write_evidence(output, evidence, secret=caller.secret)
        print(json.dumps(evidence, sort_keys=True, indent=2))
        return 0
    finally:
        if state_fd >= 0:
            os.close(state_fd)
        if not state_removed:
            try:
                state_path.unlink()
            except FileNotFoundError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
