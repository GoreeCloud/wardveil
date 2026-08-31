#!/usr/bin/env python3
"""Validate source-controlled Wardveil Scan capacity acceptance wiring and non-claims."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require(text: str, needle: str, label: str) -> None:
    if needle not in text:
        raise SystemExit(f"missing {label}: {needle}")


def main() -> int:
    service = (ROOT / "reference" / "wardveil_scan_service.py").read_text(encoding="utf-8")
    acceptance = (ROOT / "scripts" / "accept_wardveil_scan_capacity.py").read_text(
        encoding="utf-8"
    )
    helper_tests = (
        ROOT / "scripts" / "test_wardveil_scan_capacity_acceptance.py"
    ).read_text(encoding="utf-8")
    validation_workflow = (
        ROOT / ".github" / "workflows" / "validate-scan-service.yml"
    ).read_text(encoding="utf-8")
    deployment_workflow = (
        ROOT / ".github" / "workflows" / "deploy-scan-service-production.yml"
    ).read_text(encoding="utf-8")

    require(service, "threading.BoundedSemaphore(max_concurrent_scans)", "bounded semaphore")
    require(service, "scan_slots.acquire(blocking=False)", "non-blocking capacity claim")
    require(service, '"scan_service_busy"', "bounded busy envelope")
    require(service, "HTTPStatus.SERVICE_UNAVAILABLE", "capacity HTTP status")

    require(acceptance, 'LOOPBACK_URL = "http://127.0.0.1:8791"', "loopback target")
    require(acceptance, 'SERVICE_NAME = "wardveil-scan.service"', "fixed service")
    require(acceptance, "if os.geteuid() != 0", "root execution requirement")
    require(
        acceptance,
        'environment.get("WARDVEIL_SCAN_MAX_CONCURRENT_SCANS", "").strip()',
        "live process concurrency derivation",
    )
    require(acceptance, "open_held_authenticated_request", "authenticated held request")
    require(acceptance, 'payload != {"error": "scan_service_busy"}', "exact busy assertion")
    require(acceptance, '"capacity_concurrency_exhaustion": "passed"', "capacity evidence")
    require(acceptance, '"service_restart_performed": False', "no-restart evidence")
    require(acceptance, '"wardveil_invocation_unchanged": True', "invocation evidence")
    require(acceptance, '"caller_secret_in_evidence": False', "secret non-leakage")
    require(acceptance, '"raw_resource_content_in_evidence": False', "content non-leakage")
    require(
        acceptance,
        '"production_service_identity": "not_proven_by_acceptance"',
        "service-identity non-claim",
    )
    require(
        acceptance,
        '"multi_host_capacity_behavior": "not_proven"',
        "multi-host non-claim",
    )
    require(
        acceptance,
        '"production_runtime_acceptance": "unaccepted"',
        "production non-claim",
    )
    require(acceptance, '"protection_claim_authority": False', "claim-authority non-claim")

    if "atomic_replace" in acceptance:
        raise SystemExit("capacity acceptance must not mutate the caller registry")
    if "systemctl restart" in acceptance:
        raise SystemExit("capacity acceptance must not restart Wardveil Scan")

    require(helper_tests, "test_header_only_request_is_authenticated_without_body", "held request test")
    require(helper_tests, "test_configured_concurrency_default_and_bounds", "concurrency parser test")
    require(helper_tests, "test_evidence_is_private_and_secret_free", "evidence privacy test")

    for path in (
        "scripts/accept_wardveil_scan_capacity.py",
        "scripts/test_wardveil_scan_capacity_acceptance.py",
        "scripts/validate_wardveil_scan_capacity_acceptance.py",
    ):
        require(validation_workflow, path, f"validation workflow reference for {path}")

    require(
        deployment_workflow,
        "scripts/accept_wardveil_scan_capacity.py",
        "production bundle capacity harness",
    )
    require(
        deployment_workflow,
        'capacity_evidence="$base/evidence/$revision-capacity.json"',
        "production capacity evidence path",
    )
    require(
        deployment_workflow,
        'python3 "$release/scripts/accept_wardveil_scan_capacity.py"',
        "production capacity execution",
    )
    require(
        deployment_workflow,
        'evidence["capacity_concurrency_exhaustion"] == "passed"',
        "production capacity evidence validation",
    )
    require(
        deployment_workflow,
        'evidence["production_runtime_acceptance"] == "unaccepted"',
        "production runtime non-claim validation",
    )
    require(
        deployment_workflow,
        'evidence["protection_claim_authority"] is False',
        "protection claim non-claim validation",
    )

    print("Wardveil Scan capacity acceptance wiring validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
