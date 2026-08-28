#!/usr/bin/env python3
"""Validate the source-controlled Wardveil authenticated Scan service boundary."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVICE = ROOT / "reference" / "wardveil_scan_service.py"
RUNNER = ROOT / "scripts" / "serve_wardveil_scan.py"
PROBE = ROOT / "scripts" / "probe_wardveil_scan_service.py"
UNIT = ROOT / "deployment" / "scan-service" / "wardveil-scan.service"
ENV = ROOT / "deployment" / "scan-service" / ".env.example"
CALLERS_EXAMPLE = ROOT / "deployment" / "scan-service" / "scan-callers.example.json"
README = ROOT / "deployment" / "scan-service" / "README.md"
CONTRACT = ROOT / "contracts" / "wardveil.scan-service-transport.json"
VALIDATE_WORKFLOW = ROOT / ".github" / "workflows" / "validate-scan-service.yml"
DEPLOY_WORKFLOW = ROOT / ".github" / "workflows" / "deploy-scan-service-production.yml"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def require_token(text: str, token: str, context: str) -> None:
    require(token in text, f"{context} missing required token: {token}")


def forbid_token(text: str, token: str, context: str) -> None:
    require(token not in text, f"{context} contains forbidden token: {token}")


def main() -> int:
    paths = (
        SERVICE,
        RUNNER,
        PROBE,
        UNIT,
        ENV,
        CALLERS_EXAMPLE,
        README,
        CONTRACT,
        VALIDATE_WORKFLOW,
        DEPLOY_WORKFLOW,
    )
    for path in paths:
        require(path.is_file(), f"missing Wardveil Scan service file: {path.relative_to(ROOT)}")

    service = SERVICE.read_text()
    runner = RUNNER.read_text()
    probe = PROBE.read_text()
    unit = UNIT.read_text()
    env_example = ENV.read_text()
    readme = README.read_text()
    validate_workflow = VALIDATE_WORKFLOW.read_text()
    deploy_workflow = DEPLOY_WORKFLOW.read_text()
    contract = json.loads(CONTRACT.read_text())
    callers_example = json.loads(CALLERS_EXAMPLE.read_text())

    endpoint = contract.get("endpoint") or {}
    auth = contract.get("request_authentication") or {}
    credential_handling = contract.get("credential_handling") or {}
    replay = contract.get("replay_protection") or {}
    response = contract.get("response") or {}

    require(contract.get("contract_version") == "0.1.0", "unexpected scan transport contract version")
    require(contract.get("foundation_version") == "0.9.0", "unexpected Wardveil foundation version")
    require(endpoint.get("bind") == "127.0.0.1:8791", "scan service must remain loopback-only")
    require(endpoint.get("public_anonymous_access_allowed") is False, "anonymous scan access must remain forbidden")
    require(endpoint.get("direct_clamav_access_allowed") is False, "applications must not access ClamAV directly")
    require(endpoint.get("authenticate_headers_before_body_ingestion") is True, "scan service must authenticate before body ingestion")
    require(endpoint.get("request_body_timeout_seconds") == 30, "unexpected request body timeout")
    require(endpoint.get("default_max_concurrent_scans") == 8, "unexpected scan concurrency default")

    require(auth.get("scheme") == "HMAC-SHA256-reference-transport", "unexpected scan authentication scheme")
    require(auth.get("production_signature_scheme_accepted") is False, "reference HMAC must not be production-accepted")
    for key in (
        "signature_binds_all_required_fields_except_signature",
        "signature_binds_body_digest",
        "constant_time_verification_required",
        "caller_resource_type_allowlist_required",
        "unknown_or_inactive_caller_fails_closed",
        "unknown_key_fails_closed",
        "digest_or_size_mismatch_fails_closed",
        "conflicting_nonce_reuse_fails_closed",
        "exact_nonce_replay_returns_identical_cached_envelope",
    ):
        require(auth.get(key) is True, f"scan authentication invariant must be true: {key}")

    require(credential_handling.get("inline_secret_environment_variable_allowed") is False, "inline scan secret environment values must remain forbidden")
    require(credential_handling.get("systemd_load_credential_required") is True, "systemd LoadCredential must remain required")
    require(credential_handling.get("production_secret_file") == "/etc/goreecloud/wardveil/scan-callers.json", "unexpected scan credential path")
    require(credential_handling.get("caller_key_rotation_and_revocation_production_accepted") is False, "key lifecycle must remain runtime-unaccepted")

    require(replay.get("source_implementation") == "bounded-thread-safe-expiring-in-memory-ledger", "unexpected replay implementation")
    require(replay.get("thread_safe") is True, "replay ledger must be thread-safe")
    require(replay.get("default_max_entries") == 4096, "unexpected replay capacity")
    require(replay.get("default_ttl_seconds") == 180, "unexpected replay TTL")
    require(replay.get("capacity_exhaustion_fails_closed") is True, "replay capacity must fail closed")
    require(replay.get("multi_instance_durable_replay_protection_accepted") is False, "in-memory replay must not imply multi-instance acceptance")

    require(response.get("shape") == "consumer_scan_envelope", "scan response must use consumer envelope")
    require(response.get("scan_record_result_field") == "result", "consumer envelope must use result")
    require(response.get("generic_scan_result_field_allowed_in_consumer_envelope") is False, "consumer envelope must reject scan_result")
    require(contract.get("production_runtime_status") == "unaccepted", "scan transport runtime must remain unaccepted")

    for token in (
        'LOOPBACK_HOST = "127.0.0.1"',
        "X-Wardveil-Caller-ID",
        "X-Wardveil-Key-ID",
        "X-Wardveil-Timestamp",
        "X-Wardveil-Nonce",
        "X-Wardveil-Signature",
        "hmac.compare_digest",
        "authenticate_request",
        "threading.Lock",
        "threading.BoundedSemaphore",
        "scan_replay_capacity_exhausted",
        "REQUEST_BODY_TIMEOUT_SECONDS",
        '"result": finding.result',
        "scan_request_rejected",
    ):
        require_token(service, token, "scan service")
    forbid_token(service, '"scan_result": finding.result', "scan service")
    forbid_token(service, 'LOOPBACK_HOST = "0.0.0.0"', "scan service")

    for token in (
        "WARDVEIL_SCAN_CALLERS_FILE",
        "CREDENTIALS_DIRECTORY",
        "wardveil-scan-callers.json",
        "InMemoryReplayLedger",
        "WARDVEIL_SCAN_REPLAY_MAX_ENTRIES",
        "WARDVEIL_SCAN_REPLAY_TTL_SECONDS",
        "WARDVEIL_SCAN_MAX_CONCURRENT_SCANS",
    ):
        require_token(runner, token, "scan service runner")
    forbid_token(runner, "WARDVEIL_SCAN_SERVICE_TOKEN", "scan service runner")
    forbid_token(runner, "WARDVEIL_SCAN_CALLERS_JSON", "scan service runner")

    for token in (
        "DynamicUser=yes",
        "LoadCredential=wardveil-scan-callers.json:/etc/goreecloud/wardveil/scan-callers.json",
        "WorkingDirectory=/opt/goreecloud/wardveil/scan-service/current",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "ProtectHostname=yes",
        "CapabilityBoundingSet=",
        "IPAddressDeny=any",
        "IPAddressAllow=127.0.0.0/8",
    ):
        require_token(unit, token, "systemd unit")
    forbid_token(unit, "0.0.0.0", "systemd unit")

    for forbidden in (
        "TOKEN=",
        "SECRET=",
        "PASSWORD=",
        "WARDVEIL_SCAN_CALLERS_JSON",
        "REPLACE_WITH_PRODUCTION_SECRET",
    ):
        forbid_token(env_example, forbidden, "scan service .env.example")
    for token in (
        "WARDVEIL_SCAN_SERVICE_PORT=8791",
        "WARDVEIL_SCAN_MAX_CONCURRENT_SCANS=8",
        "WARDVEIL_SCAN_REPLAY_MAX_ENTRIES=4096",
        "WARDVEIL_SCAN_REPLAY_TTL_SECONDS=180",
    ):
        require_token(env_example, token, "scan service .env.example")

    require(isinstance(callers_example, list) and len(callers_example) == 1, "scan caller example must contain one sanitized entry")
    example = callers_example[0]
    secret = example.get("secret")
    require(isinstance(secret, str) and secret.startswith("REPLACE_"), "scan caller example must use a replacement placeholder")
    require(len(secret.encode("utf-8")) < 32, "scan caller example placeholder must remain intentionally unusable")
    require(example.get("resource_types") == ["drive_file"], "scan caller example must stay least-privilege")

    for token in (
        "systemd `LoadCredential`",
        "scan_record` whose result field is `result`",
        "does not use `scan_result`",
        "authenticate",
        "before the service reads",
        "single process instance",
        "production runtime acceptance: `unaccepted`",
    ):
        require_token(readme, token, "scan service README")

    for token in (
        "credentials_from_json",
        "sign_scan_request",
        "consumer_envelope_compatibility",
        '"application_consumer_integration": "not_proven_by_probe"',
        '"production_service_identity": "not_proven_by_probe"',
        '"quarantine_execution": "not_proven_by_probe"',
        '"production_runtime_acceptance": "unaccepted"',
    ):
        require_token(probe, token, "scan runtime probe")

    for token in (
        "ref: ${{ github.event_name == 'pull_request' && github.event.pull_request.head.sha || github.sha }}",
        "scripts/test_wardveil_scan_service.py",
        "scripts/validate_wardveil_scan_service.py",
        "scripts/probe_wardveil_scan_service.py",
        "contracts/wardveil.scan-service-transport.json",
    ):
        require_token(validate_workflow, token, "scan service validation workflow")

    for token in (
        "workflow_dispatch:",
        "expected_sha:",
        "test \"$GITHUB_SHA\" = \"$EXPECTED_SHA\"",
        "persist-credentials: false",
        "StrictHostKeyChecking=yes",
        "/etc/goreecloud/wardveil/scan-callers.json",
        "LoadCredential",
        "127.0.0.1:8791/healthz",
        "scripts/probe_wardveil_scan_service.py",
        "consumer_envelope_compatibility",
        "application_consumer_integration",
        "production_runtime_acceptance",
        "unaccepted",
    ):
        require_token(deploy_workflow, token, "scan service deployment workflow")
    forbid_token(deploy_workflow, "WARDVEIL_SCAN_SERVICE_TOKEN", "scan service deployment workflow")
    forbid_token(deploy_workflow, "0.0.0.0:8791", "scan service deployment workflow")

    print("Wardveil authenticated Scan service deployment contract valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
