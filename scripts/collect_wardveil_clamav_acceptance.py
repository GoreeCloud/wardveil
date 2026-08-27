#!/usr/bin/env python3
"""Collect bounded live acceptance evidence for a deployed Wardveil ClamAV runtime.

This collector verifies the scanner runtime only. It deliberately does not promote
Wardveil's broader production acceptance state, because application transport and
authorized quarantine execution remain separate evidence requirements.
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from reference.wardveil_clamav import ClamAVClient, ClamAVConfig
from reference.wardveil_clamav_runtime import (
    collect_clamav_health,
    config_from_env,
    gate_clamav_verdict,
    policy_from_env,
)


def _eicar_test_bytes() -> bytes:
    # Assemble the standard harmless EICAR antivirus test string at runtime so the
    # repository does not contain a standalone scanner-triggering fixture file.
    return (
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
        "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    ).encode("ascii")


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--expected-revision",
        default=os.environ.get("WARDVEIL_DEPLOYED_REVISION", "unknown"),
    )
    parser.add_argument(
        "--error-port",
        type=int,
        default=int(os.environ.get("WARDVEIL_CLAMAV_ACCEPTANCE_ERROR_PORT", "1")),
        help="Loopback port expected to refuse a connection for the fail-closed test.",
    )
    args = parser.parse_args()

    observed_at = datetime.now(timezone.utc)
    client = ClamAVClient(config_from_env())
    health = collect_clamav_health(
        client,
        policy=policy_from_env(),
        now=observed_at,
    )

    clean_payload = b"Wardveil controlled clean acceptance sample\n"
    clean_verdict = client.scan_bytes(clean_payload)
    clean_finding = gate_clamav_verdict(
        clean_verdict,
        health,
        resource_id="acceptance:clamav:clean-control",
        now=observed_at,
    )

    eicar_verdict = client.scan_bytes(_eicar_test_bytes())
    eicar_finding = gate_clamav_verdict(
        eicar_verdict,
        health,
        resource_id="acceptance:clamav:eicar-control",
        now=observed_at,
    )

    error_config = ClamAVConfig(
        unix_socket=None,
        tcp_host="127.0.0.1",
        tcp_port=args.error_port,
        timeout_seconds=0.5,
        max_stream_bytes=client.config.max_stream_bytes,
        chunk_bytes=client.config.chunk_bytes,
        producer_id=client.config.producer_id,
    )
    error_verdict = ClamAVClient(error_config).scan_bytes(clean_payload)
    error_finding = gate_clamav_verdict(
        error_verdict,
        health,
        resource_id="acceptance:clamav:unavailable-control",
        now=observed_at,
    )

    checks = {
        "daemon_reachable": health.daemon_reachable,
        "engine_version": bool(health.engine_version),
        "signature_database_version": bool(health.database_version),
        "signature_database_timestamp": health.database_updated_at is not None,
        "signature_freshness": health.signature_freshness == "current",
        "healthy_runtime": health.runtime_state == "healthy" and health.clean_verdicts_eligible,
        "clean_control_test": (
            clean_verdict.completed
            and not clean_verdict.malware_match
            and clean_finding.result == "clean"
        ),
        "successful_eicar_test": (
            eicar_verdict.completed
            and eicar_verdict.malware_match
            and eicar_finding.result == "malicious"
        ),
        "error_fail_closed_test": (
            not error_verdict.completed
            and not error_verdict.malware_match
            and error_finding.result == "unknown"
        ),
    }
    runtime_passed = all(checks.values())

    manifest = {
        "schema_version": 1,
        "component": "Wardveil ClamAV malware scanning runtime",
        "environment": "production",
        "deployed_revision": args.expected_revision,
        "observed_at": _iso(observed_at),
        "runtime_evidence_status": "passed" if runtime_passed else "failed",
        "production_runtime_acceptance": "unaccepted",
        "checks": checks,
        "health": health.as_dict(),
        "clean_control": {
            "completed": clean_verdict.completed,
            "malware_match": clean_verdict.malware_match,
            "wardveil_result": clean_finding.result,
            "digest_sha256": clean_verdict.digest_sha256,
        },
        "eicar_control": {
            "completed": eicar_verdict.completed,
            "malware_match": eicar_verdict.malware_match,
            "signature": eicar_verdict.signature,
            "wardveil_result": eicar_finding.result,
            "digest_sha256": eicar_verdict.digest_sha256,
        },
        "unavailable_control": {
            "completed": error_verdict.completed,
            "malware_match": error_verdict.malware_match,
            "wardveil_result": error_finding.result,
            "error_code": error_verdict.error_code,
        },
        "remaining_acceptance_requirements": [
            "application_consumer_integration",
            "quarantine_execution_evidence",
        ],
        "protection_claim_authority": False,
    }

    encoded = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if runtime_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
