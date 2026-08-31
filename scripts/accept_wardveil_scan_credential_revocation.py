#!/usr/bin/env python3
"""Prove Wardveil Scan caller credential rotation and revocation across real restarts.

This acceptance uses a temporary acceptance-only caller added alongside the existing
production registry. Existing caller entries are preserved byte-for-byte on final
restore and are never rotated by this probe. The temporary caller is accepted,
rotated, rejected under its old key, accepted under its replacement key, disabled,
and rejected again after a subsequent wardveil-scan.service restart.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
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
    CallerCredential,
    ScanServiceRequest,
    credentials_from_json,
    sign_scan_request,
)

LOOPBACK_URL = "http://127.0.0.1:8791"
SERVICE_NAME = "wardveil-scan.service"
RESOURCE_TYPE = "drive_file"
CONTROL_BODY = b"Wardveil credential revocation acceptance control\n"
CONTROL_EVIDENCE_MARKER = CONTROL_BODY.rstrip()
HTTP_TIMEOUT_SECONDS = 10
HEALTH_TIMEOUT_SECONDS = 20.0
MAX_HTTP_RESPONSE_BYTES = 1 << 20
ALLOWED_REGISTRY_MODES = {0o400, 0o600}


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
        "X-Wardveil-Action": request.action,
        "X-Wardveil-Resource-Type": request.resource_type,
        "X-Wardveil-Resource-ID": request.resource_id,
        "X-Wardveil-Correlation-ID": request.correlation_id,
        "X-Wardveil-Digest-SHA256": request.digest_sha256,
        "X-Wardveil-Size-Bytes": str(request.size_bytes),
        "X-Wardveil-Signature": request.signature,
    }


def signed_request(caller: CallerCredential, body: bytes, *, phase: str) -> ScanServiceRequest:
    request = ScanServiceRequest(
        caller_id=caller.caller_id,
        key_id=caller.key_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        nonce=f"credential-{phase}-{uuid4()}",
        action="runtime_acceptance_probe",
        resource_type=RESOURCE_TYPE,
        resource_id=f"wardveil-credential-{phase}:{uuid4()}",
        digest_sha256=hashlib.sha256(body).hexdigest(),
        size_bytes=len(body),
        correlation_id=f"credential-{phase}-{uuid4()}",
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
        fail(f"expected accepted Wardveil Scan request, got HTTP {status}")
    record = payload.get("scan_record")
    if not isinstance(record, dict) or record.get("result") != "clean":
        fail("accepted credential control did not return a clean Wardveil Scan finding")
    if payload.get("resource_id") != request.resource_id:
        fail("accepted credential control returned the wrong resource identity")
    if payload.get("resource_digest_sha256") != request.digest_sha256:
        fail("accepted credential control returned the wrong content digest")


def assert_rejected(status: int, payload: dict) -> None:
    if status != 401:
        fail(f"revoked Wardveil Scan credential was not rejected with HTTP 401: {status}")
    if payload != {"error": "scan_request_rejected"}:
        fail("revoked Wardveil Scan credential did not receive the generic rejection envelope")


def health(url: str) -> dict:
    try:
        with urllib.request.urlopen(url.rstrip("/") + "/healthz", timeout=3) as response:
            if response.status != 200:
                fail(f"Wardveil Scan health returned HTTP {response.status}")
            payload = read_http_json(response)
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Wardveil Scan health transport failed: {exc.reason}") from exc
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


def restart_service_and_wait(service: str, url: str) -> tuple[str, str]:
    before = systemctl_value(service, "InvocationID")
    if not before or not service_active(service):
        fail("Wardveil Scan service is not active before credential lifecycle restart")
    subprocess.run(["systemctl", "restart", service], check=True)

    deadline = time.monotonic() + HEALTH_TIMEOUT_SECONDS
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if service_active(service):
            try:
                health(url)
                break
            except Exception as exc:  # noqa: BLE001 - surfaced after bounded polling
                last_error = exc
        time.sleep(0.2)
    else:
        if last_error is not None:
            raise SystemExit(f"Wardveil Scan did not recover after restart: {last_error}")
        fail("Wardveil Scan did not recover after restart")

    after = systemctl_value(service, "InvocationID")
    if not after or after == before:
        fail("systemd invocation identity did not change across credential lifecycle restart")
    return before, after


def load_registry(path: Path) -> tuple[bytes, os.stat_result, list[dict], tuple[bytes, ...]]:
    if not path.is_absolute():
        fail("Wardveil Scan caller credential path must be absolute")
    if path.is_symlink() or not path.is_file():
        fail("Wardveil Scan caller credential path must be a regular non-symlink file")
    metadata = path.stat()
    mode = stat.S_IMODE(metadata.st_mode)
    if mode not in ALLOWED_REGISTRY_MODES:
        fail("Wardveil Scan caller credential file must be mode 0400 or 0600")
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit("Wardveil Scan caller credential file must be UTF-8") from exc
    credentials = credentials_from_json(text)
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SystemExit("Wardveil Scan caller credential file must be valid JSON") from exc
    if not isinstance(payload, list):
        fail("Wardveil Scan caller credential registry must be a list")
    secrets_found = tuple(item.secret for item in credentials.values())
    return raw, metadata, payload, secrets_found


def acceptance_entry(caller: CallerCredential) -> dict:
    return {
        "caller_id": caller.caller_id,
        "key_id": caller.key_id,
        "secret": caller.secret.decode("ascii"),
        "resource_types": sorted(caller.resource_types),
        "active": caller.active,
    }


def registry_with_temporary_caller(
    original_entries: list[dict],
    caller: CallerCredential,
) -> bytes:
    if any(str(item.get("caller_id", "")) == caller.caller_id for item in original_entries):
        fail("temporary Wardveil acceptance caller unexpectedly collides with existing registry")
    payload = [*original_entries, acceptance_entry(caller)]
    # Re-parse the exact candidate before it can reach the credential file.
    raw = json.dumps(payload, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    credentials_from_json(raw.decode("utf-8"))
    return raw


def atomic_replace(path: Path, raw: bytes, metadata: os.stat_result) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".wardveil-scan-callers-", dir=path.parent)
    try:
        os.fchmod(fd, stat.S_IMODE(metadata.st_mode))
        os.fchown(fd, metadata.st_uid, metadata.st_gid)
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def assert_original_entries_preserved(path: Path, original_entries: list[dict], caller_id: str) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        fail("credential registry changed shape during acceptance")
    existing = [item for item in payload if str(item.get("caller_id", "")) != caller_id]
    if existing != original_entries:
        fail("existing production caller entries changed during credential acceptance")


def write_evidence(path: Path, evidence: dict, *, forbidden_secrets: tuple[bytes, ...]) -> None:
    if not path.is_absolute():
        fail("credential lifecycle evidence path must be absolute")
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(evidence, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    if CONTROL_EVIDENCE_MARKER in raw:
        fail("raw control content would leak into credential lifecycle evidence")
    for secret in forbidden_secrets:
        if secret and secret in raw:
            fail("caller secret would leak into credential lifecycle evidence")
    fd, temporary = tempfile.mkstemp(prefix=".wardveil-credential-evidence-", dir=path.parent)
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
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    if os.geteuid() != 0:
        fail("credential revocation acceptance must run as root")
    if args.url != LOOPBACK_URL:
        fail("credential revocation acceptance accepts only the loopback Wardveil Scan URL")
    if args.service != SERVICE_NAME:
        fail("credential revocation acceptance accepts only wardveil-scan.service")
    if (
        len(args.source_revision) != 40
        or any(ch not in "0123456789abcdef" for ch in args.source_revision)
    ):
        fail("--source-revision must be an exact lowercase 40-character Git SHA")

    callers_path = Path(args.callers_file)
    output_path = Path(args.output)
    original_raw, original_metadata, original_entries, existing_secrets = load_registry(callers_path)
    original_hash = hashlib.sha256(original_raw).hexdigest()
    caller_id = f"wardveil-revocation-acceptance-{secrets.token_hex(8)}"
    old_secret = secrets.token_urlsafe(48).encode("ascii")
    replacement_secret = secrets.token_urlsafe(48).encode("ascii")
    old_caller = CallerCredential(
        caller_id=caller_id,
        key_id="pre-revoke",
        secret=old_secret,
        resource_types=frozenset({RESOURCE_TYPE}),
        active=True,
    )
    replacement_caller = CallerCredential(
        caller_id=caller_id,
        key_id="post-rotate",
        secret=replacement_secret,
        resource_types=frozenset({RESOURCE_TYPE}),
        active=True,
    )
    disabled_replacement = replace(replacement_caller, active=False)
    for caller in (old_caller, replacement_caller, disabled_replacement):
        caller.validate()

    initial_invocation = systemctl_value(args.service, "InvocationID")
    if not initial_invocation or not service_active(args.service):
        fail("Wardveil Scan service is not active before credential revocation acceptance")
    health(args.url)

    lifecycle_complete = False
    restore_error: Exception | None = None
    try:
        atomic_replace(
            callers_path,
            registry_with_temporary_caller(original_entries, old_caller),
            original_metadata,
        )
        assert_original_entries_preserved(callers_path, original_entries, caller_id)
        _, old_loaded_invocation = restart_service_and_wait(args.service, args.url)
        old_request = signed_request(old_caller, CONTROL_BODY, phase="old-accepted")
        status, payload = post_scan(args.url, old_request, CONTROL_BODY)
        assert_clean(status, payload, old_request)

        atomic_replace(
            callers_path,
            registry_with_temporary_caller(original_entries, replacement_caller),
            original_metadata,
        )
        assert_original_entries_preserved(callers_path, original_entries, caller_id)
        _, rotated_invocation = restart_service_and_wait(args.service, args.url)
        if rotated_invocation == old_loaded_invocation:
            fail("Wardveil Scan invocation did not change after credential rotation")

        revoked_old_request = signed_request(old_caller, CONTROL_BODY, phase="old-after-rotation")
        status, payload = post_scan(args.url, revoked_old_request, CONTROL_BODY)
        assert_rejected(status, payload)

        replacement_request = signed_request(
            replacement_caller,
            CONTROL_BODY,
            phase="replacement-accepted",
        )
        status, payload = post_scan(args.url, replacement_request, CONTROL_BODY)
        assert_clean(status, payload, replacement_request)

        atomic_replace(
            callers_path,
            registry_with_temporary_caller(original_entries, disabled_replacement),
            original_metadata,
        )
        assert_original_entries_preserved(callers_path, original_entries, caller_id)
        _, revoked_invocation = restart_service_and_wait(args.service, args.url)
        if revoked_invocation == rotated_invocation:
            fail("Wardveil Scan invocation did not change after explicit credential revocation")

        disabled_request = signed_request(
            replacement_caller,
            CONTROL_BODY,
            phase="replacement-after-revocation",
        )
        status, payload = post_scan(args.url, disabled_request, CONTROL_BODY)
        assert_rejected(status, payload)
        lifecycle_complete = True
    finally:
        try:
            atomic_replace(callers_path, original_raw, original_metadata)
            restart_service_and_wait(args.service, args.url)
        except Exception as exc:  # noqa: BLE001 - restoration failure must dominate acceptance
            restore_error = exc

    if restore_error is not None:
        raise SystemExit(f"failed to restore Wardveil Scan caller registry: {restore_error}")
    if not lifecycle_complete:
        fail("Wardveil Scan credential lifecycle did not complete")

    restored_raw = callers_path.read_bytes()
    restored_metadata = callers_path.stat()
    if restored_raw != original_raw or hashlib.sha256(restored_raw).hexdigest() != original_hash:
        fail("Wardveil Scan caller registry was not restored byte-for-byte")
    if stat.S_IMODE(restored_metadata.st_mode) != stat.S_IMODE(original_metadata.st_mode):
        fail("Wardveil Scan caller registry mode changed after acceptance")
    if (restored_metadata.st_uid, restored_metadata.st_gid) != (
        original_metadata.st_uid,
        original_metadata.st_gid,
    ):
        fail("Wardveil Scan caller registry ownership changed after acceptance")
    post_health = health(args.url)

    evidence = {
        "component": "Wardveil Scan credential rotation and revocation acceptance",
        "wardveil_revision": args.source_revision,
        "wardveil_endpoint": args.url.rstrip("/") + "/v1/scan",
        "service": args.service,
        "temporary_acceptance_caller": "ephemeral",
        "temporary_scope": RESOURCE_TYPE,
        "initial_temporary_credential": "passed",
        "service_restart_after_initial_credential": "passed",
        "old_credential_after_rotation": "rejected",
        "replacement_credential_after_rotation": "passed",
        "service_restart_after_rotation": "passed",
        "replacement_credential_after_explicit_revocation": "rejected",
        "service_restart_after_explicit_revocation": "passed",
        "generic_rejection_envelope": "passed",
        "existing_production_caller_entries_preserved": True,
        "original_credential_registry_restored": True,
        "original_credential_registry_hash_restored": True,
        "original_credential_registry_mode_restored": True,
        "original_credential_registry_owner_restored": True,
        "temporary_acceptance_credential_removed": True,
        "post_acceptance_health": "passed",
        "post_acceptance_health_runtime_status": post_health["production_runtime_status"],
        "revoked_credential_lifecycle": "passed",
        "raw_resource_content_in_evidence": False,
        "caller_secret_in_evidence": False,
        "application_consumer_integration": "not_proven_by_acceptance",
        "production_service_identity": "not_proven_by_acceptance",
        "production_runtime_acceptance": "unaccepted",
        "protection_claim_authority": False,
    }
    write_evidence(
        output_path,
        evidence,
        forbidden_secrets=(*existing_secrets, old_secret, replacement_secret),
    )
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
