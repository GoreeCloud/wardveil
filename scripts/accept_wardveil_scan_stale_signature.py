#!/usr/bin/env python3
"""Accept Wardveil Scan stale ClamAV signature policy on a live target host.

This harness never changes the system clock, ClamAV signature database, container,
active wardveil-scan.service, or production caller registry. It connects to the
live ClamAV daemon, injects only the Wardveil service's supported in-process clock,
and proves that stale signature health removes clean-verdict eligibility while a
positive malware match remains malicious. A fresh-clock clean request must then
recover to clean.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_clamav import ClamAVClient  # noqa: E402
from reference.wardveil_clamav_runtime import (  # noqa: E402
    ClamAVRuntimePolicy,
    collect_clamav_health,
    config_from_env,
    policy_from_env,
)
from reference.wardveil_scan_service import (  # noqa: E402
    CallerCredential,
    ScanServiceRequest,
    WardveilScanService,
    sign_scan_request,
)


def eicar_test_bytes() -> bytes:
    return (
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
        "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    ).encode("ascii")


def git_blob_sha1(path: Path) -> str:
    data = path.read_bytes()
    digest = hashlib.sha1()
    digest.update(f"blob {len(data)}\0".encode("ascii"))
    digest.update(data)
    return digest.hexdigest()


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def make_request(
    credential: CallerCredential,
    content: bytes,
    *,
    now: datetime,
    resource_id: str,
) -> ScanServiceRequest:
    digest = hashlib.sha256(content).hexdigest()
    request = ScanServiceRequest(
        caller_id=credential.caller_id,
        key_id=credential.key_id,
        timestamp=iso(now),
        nonce=f"accept-{uuid4().hex}",
        resource_type="drive_file",
        resource_id=resource_id,
        digest_sha256=digest,
        size_bytes=len(content),
        action="scan",
        correlation_id=f"accept-{uuid4().hex}",
        signature="0" * 64,
    )
    return replace(
        request,
        signature=sign_scan_request(request, credential.secret),
    )


def scan_at(
    client: ClamAVClient,
    policy: ClamAVRuntimePolicy,
    credential: CallerCredential,
    content: bytes,
    *,
    now: datetime,
    resource_id: str,
) -> dict:
    service = WardveilScanService(
        credentials={(credential.caller_id, credential.key_id): credential},
        client=client,
        policy=policy,
        now=lambda: now,
    )
    return service.scan(
        make_request(
            credential,
            content,
            now=now,
            resource_id=resource_id,
        ),
        content,
    )


def exercise_signature_freshness(
    client: ClamAVClient,
    policy: ClamAVRuntimePolicy,
    *,
    baseline_now: datetime | None = None,
    recovery_now: datetime | None = None,
) -> dict:
    baseline_now = (baseline_now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    baseline_health = collect_clamav_health(client, policy=policy, now=baseline_now)
    if not baseline_health.clean_verdicts_eligible:
        raise RuntimeError("baseline_scanner_health_not_clean_eligible")
    if baseline_health.database_updated_at is None:
        raise RuntimeError("baseline_signature_timestamp_missing")

    credential = CallerCredential(
        caller_id="wardveil-stale-signature-acceptance",
        key_id="ephemeral",
        secret=secrets.token_bytes(32),
        resource_types=frozenset({"drive_file"}),
        active=True,
    )
    credential.validate()

    clean = b"Wardveil controlled stale-signature clean sample\n"
    baseline_clean = scan_at(
        client,
        policy,
        credential,
        clean,
        now=baseline_now,
        resource_id="acceptance:stale-signature:baseline-clean",
    )
    if baseline_clean["scan_record"]["result"] != "clean":
        raise RuntimeError("baseline_clean_result_not_clean")

    stale_now = baseline_health.database_updated_at + policy.max_signature_age + timedelta(seconds=1)
    stale_health = collect_clamav_health(client, policy=policy, now=stale_now)
    if stale_health.signature_freshness != "stale":
        raise RuntimeError("controlled_stale_health_not_stale")
    if stale_health.runtime_state != "degraded":
        raise RuntimeError("controlled_stale_health_not_degraded")
    if "signature_database_stale" not in stale_health.degraded_reasons:
        raise RuntimeError("controlled_stale_reason_missing")
    if stale_health.clean_verdicts_eligible:
        raise RuntimeError("controlled_stale_clean_verdicts_still_eligible")

    stale_clean = scan_at(
        client,
        policy,
        credential,
        clean,
        now=stale_now,
        resource_id="acceptance:stale-signature:stale-clean",
    )
    if stale_clean["scan_record"]["result"] != "unknown":
        raise RuntimeError("stale_clean_did_not_fail_closed_to_unknown")

    stale_eicar = scan_at(
        client,
        policy,
        credential,
        eicar_test_bytes(),
        now=stale_now,
        resource_id="acceptance:stale-signature:stale-eicar",
    )
    if stale_eicar["scan_record"]["result"] != "malicious":
        raise RuntimeError("stale_health_erased_positive_malware_finding")

    recovery_now = (recovery_now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    recovery_health = collect_clamav_health(client, policy=policy, now=recovery_now)
    if not recovery_health.clean_verdicts_eligible:
        raise RuntimeError("recovery_scanner_health_not_clean_eligible")
    recovery_clean = scan_at(
        client,
        policy,
        credential,
        clean,
        now=recovery_now,
        resource_id="acceptance:stale-signature:recovery-clean",
    )
    if recovery_clean["scan_record"]["result"] != "clean":
        raise RuntimeError("recovery_clean_result_not_clean")

    return {
        "baseline_health": baseline_health,
        "baseline_clean": baseline_clean,
        "stale_now": stale_now,
        "stale_health": stale_health,
        "stale_clean": stale_clean,
        "stale_eicar": stale_eicar,
        "recovery_health": recovery_health,
        "recovery_clean": recovery_clean,
    }


def write_exclusive(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
    except Exception:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--deployed-scan-revision", required=True)
    parser.add_argument("--deployed-scan-release", required=True, type=Path)
    parser.add_argument("--deployed-clamav-revision", required=True)
    parser.add_argument("--expected-runtime-policy-blob", required=True)
    args = parser.parse_args()

    local_policy = ROOT / "reference" / "wardveil_clamav_runtime.py"
    deployed_policy = args.deployed_scan_release / "reference" / "wardveil_clamav_runtime.py"
    if not deployed_policy.is_file() or deployed_policy.is_symlink():
        raise SystemExit("deployed Scan runtime policy file is missing or unsafe")

    local_blob = git_blob_sha1(local_policy)
    deployed_blob = git_blob_sha1(deployed_policy)
    if local_blob != args.expected_runtime_policy_blob:
        raise SystemExit("acceptance source runtime-policy blob mismatch")
    if deployed_blob != args.expected_runtime_policy_blob:
        raise SystemExit("deployed Scan runtime-policy blob mismatch")
    if local_policy.read_bytes() != deployed_policy.read_bytes():
        raise SystemExit("acceptance and deployed runtime-policy bytes differ")

    client = ClamAVClient(config_from_env())
    policy = policy_from_env()
    observed_at = datetime.now(timezone.utc)
    result = exercise_signature_freshness(
        client,
        policy,
        baseline_now=observed_at,
    )

    baseline_health = result["baseline_health"]
    stale_health = result["stale_health"]
    recovery_health = result["recovery_health"]

    manifest = {
        "schema_version": 1,
        "component": "Wardveil Scan stale ClamAV signature freshness acceptance",
        "environment": "production-target-host",
        "acceptance_mode": "controlled_clock_live_clamd",
        "wardveil_scan_revision": args.deployed_scan_revision,
        "clamav_deployment_revision": args.deployed_clamav_revision,
        "runtime_policy_git_blob_sha1": local_blob,
        "observed_at": iso(observed_at),
        "configured_max_signature_age_seconds": policy.max_signature_age.total_seconds(),
        "baseline": {
            "engine_version": baseline_health.engine_version,
            "database_version": baseline_health.database_version,
            "database_updated_at": iso(baseline_health.database_updated_at),
            "signature_freshness": baseline_health.signature_freshness,
            "runtime_state": baseline_health.runtime_state,
            "clean_verdicts_eligible": baseline_health.clean_verdicts_eligible,
            "clean_result": result["baseline_clean"]["scan_record"]["result"],
        },
        "controlled_stale": {
            "evaluation_time": iso(result["stale_now"]),
            "signature_age_seconds": stale_health.signature_age_seconds,
            "signature_freshness": stale_health.signature_freshness,
            "runtime_state": stale_health.runtime_state,
            "degraded_reasons": list(stale_health.degraded_reasons),
            "clean_verdicts_eligible": stale_health.clean_verdicts_eligible,
            "clean_result": result["stale_clean"]["scan_record"]["result"],
            "eicar_result": result["stale_eicar"]["scan_record"]["result"],
        },
        "recovery": {
            "observed_at": iso(recovery_health.observed_at),
            "signature_freshness": recovery_health.signature_freshness,
            "runtime_state": recovery_health.runtime_state,
            "clean_verdicts_eligible": recovery_health.clean_verdicts_eligible,
            "clean_result": result["recovery_clean"]["scan_record"]["result"],
        },
        "controlled_stale_signature_policy_acceptance": "passed",
        "stale_clean_fail_closed": "passed",
        "positive_malware_evidence_preserved_when_stale": "passed",
        "fresh_health_recovery": "passed",
        "system_clock_changed": False,
        "production_signature_database_modified": False,
        "production_clamav_restarted": False,
        "production_wardveil_scan_restarted": False,
        "production_caller_registry_used": False,
        "production_caller_registry_modified": False,
        "acceptance_only_secret_in_evidence": False,
        "raw_control_content_in_evidence": False,
        "actual_production_signature_database_stale_event": "not_performed",
        "multi_host_behavior": "not_proven",
        "production_runtime_acceptance": "unaccepted",
        "protection_claim_authority": False,
    }

    encoded = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    write_exclusive(args.output, encoded)
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
