#!/usr/bin/env python3
"""Validate Wardveil ClamAV runtime-health and deployment invariants."""

from __future__ import annotations

import json
from pathlib import Path

from validate_ai_consumer_source_evidence import main as validate_ai_consumer_source_evidence
from validate_browser_consumer_source_evidence import main as validate_browser_consumer_source_evidence
from validate_drive_consumer_source_evidence import main as validate_drive_consumer_source_evidence
from validate_mail_consumer_source_evidence import main as validate_mail_consumer_source_evidence

ROOT = Path(__file__).resolve().parents[1]
ACCEPTANCE = ROOT / "contracts" / "wardveil.clamav.runtime-acceptance.json"
HEALTH_SCHEMA = ROOT / "contracts" / "wardveil.clamav.health.schema.json"
RUNTIME = ROOT / "reference" / "wardveil_clamav_runtime.py"
DEPLOYMENT = ROOT / "deployment" / "clamav" / "compose.yaml"
ENV_EXAMPLE = ROOT / "deployment" / "clamav" / ".env.example"
DEPLOYMENT_DOC = ROOT / "deployment" / "clamav" / "README.md"
INTEGRATION_DOC = ROOT / "docs/CLAMAV-INTEGRATION.md"
ACCEPTANCE_COLLECTOR = ROOT / "scripts" / "collect_wardveil_clamav_acceptance.py"
DEPLOYMENT_WORKFLOW = ROOT / ".github" / "workflows" / "deploy-clamav-production.yml"

FORBIDDEN_KEYS = {
    "password", "passphrase", "private_key", "api_key", "access_token",
    "refresh_token", "recovery_code", "mfa_seed", "session_token",
    "client_secret", "authorization", "cookie",
}
EXPECTED_ACCEPTANCE = {
    "daemon_reachable",
    "engine_version",
    "signature_database_version",
    "signature_database_timestamp",
    "signature_freshness",
    "successful_eicar_test",
    "clean_control_test",
    "error_fail_closed_test",
    "application_consumer_integration",
    "quarantine_execution_evidence",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"Wardveil ClamAV runtime validation failed: {message}")


def walk_keys(value):
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key).lower()
            yield from walk_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_keys(child)


def main() -> None:
    for path in (
        ACCEPTANCE,
        HEALTH_SCHEMA,
        RUNTIME,
        DEPLOYMENT,
        ENV_EXAMPLE,
        DEPLOYMENT_DOC,
        INTEGRATION_DOC,
        ACCEPTANCE_COLLECTOR,
        DEPLOYMENT_WORKFLOW,
    ):
        require(path.is_file(), f"missing required file: {path.relative_to(ROOT)}")

    acceptance = json.loads(ACCEPTANCE.read_text(encoding="utf-8"))
    schema = json.loads(HEALTH_SCHEMA.read_text(encoding="utf-8"))
    runtime = RUNTIME.read_text(encoding="utf-8")
    compose = DEPLOYMENT.read_text(encoding="utf-8")
    env_example = ENV_EXAMPLE.read_text(encoding="utf-8")
    docs = DEPLOYMENT_DOC.read_text(encoding="utf-8") + "\n" + INTEGRATION_DOC.read_text(encoding="utf-8")
    acceptance_collector = ACCEPTANCE_COLLECTOR.read_text(encoding="utf-8")
    deployment_workflow = DEPLOYMENT_WORKFLOW.read_text(encoding="utf-8")

    require(acceptance.get("component") == "Wardveil ClamAV malware scanning runtime", "unexpected component identity")
    require(acceptance.get("engine_role") == "replaceable-signature-scanner", "ClamAV must remain replaceable infrastructure")
    require(acceptance.get("preferred_container_image") == "clamav/clamav:1.4_base", "unexpected ClamAV LTS image baseline")
    require(acceptance.get("public_clamd_surface_allowed") is False, "public clamd exposure must remain prohibited")
    require(acceptance.get("max_signature_age_hours") == 48, "signature freshness limit must remain 48 hours")
    require(acceptance.get("clean_verdict_requires_acceptable_runtime_health") is True, "clean verdicts must require acceptable health")
    require(acceptance.get("malicious_match_remains_actionable_when_health_degraded") is True, "degraded health must not erase malware matches")
    require(acceptance.get("health_alone_authorizes_protected_by_wardveil") is False, "health alone must not authorize Wardveil protection claims")
    require(acceptance.get("production_runtime_status") == "unaccepted", "source contract must not claim production acceptance")
    require(set(acceptance.get("required_acceptance_evidence", [])) == EXPECTED_ACCEPTANCE, "runtime acceptance evidence set is incomplete or unexpected")

    require(schema.get("$id") == "urn:goreecloud:wardveil:clamav-health:0.1.0", "unexpected health schema id")
    properties = schema.get("properties", {})
    require(set(properties.get("runtime_state", {}).get("enum", [])) == {"healthy", "degraded", "unavailable", "unknown"}, "invalid runtime state vocabulary")
    require(set(properties.get("signature_freshness", {}).get("enum", [])) == {"current", "stale", "unknown"}, "invalid signature freshness vocabulary")
    require(properties.get("protection_claim_authority", {}).get("const") is False, "health schema must deny protection-claim authority")
    leaked = sorted(set(walk_keys(schema)) & FORBIDDEN_KEYS)
    require(not leaked, f"health schema contains forbidden secret-bearing fields: {', '.join(leaked)}")

    for token in (
        "health_current = health.observed_at <= observed_at < health.valid_until",
        'if finding.result != "clean" or (health.clean_verdicts_eligible and health_current):',
        '"scanner_health_not_acceptable_for_clean_verdict"',
        '"scanner_health_evidence_expired"',
        '"signature_database_stale"',
        '"scan_error_rate_high"',
        '"protection_claim_authority": False',
        '"protected_by_wardveil": False',
    ):
        require(token in runtime, f"runtime implementation missing invariant: {token}")

    require("127.0.0.1:${WARDVEIL_CLAMAV_PORT:-3310}:3310" in compose, "compose baseline must bind clamd to loopback")
    require("0.0.0.0" not in compose, "compose baseline must not expose clamd publicly")
    require("network_mode: host" not in compose, "compose baseline must not bypass loopback port policy")
    require("clamav/clamav:1.4_base" in compose, "compose baseline must use the accepted LTS feature image")
    require("/var/lib/clamav" in compose, "signature database must use persistent storage")

    for token in (
        "WARDVEIL_CLAMAV_TCP_HOST=127.0.0.1",
        "WARDVEIL_CLAMAV_MAX_SIGNATURE_AGE_HOURS=48",
        "WARDVEIL_CLAMAV_HEALTH_VALIDITY_MINUTES=5",
    ):
        require(token in env_example, f"environment template missing invariant: {token}")

    for phrase in (
        "health alone is not a broad wardveil protection claim",
        "stale, unavailable, future-dated, or otherwise unverified signature evidence downgrades a would-be clean result to `unknown`",
        "production acceptance remains `unaccepted`",
        "do not expose an unauthenticated `clamd` listener directly to the public internet",
        "guarded production deployment workflow",
    ):
        require(phrase in docs.lower(), f"documentation missing required boundary: {phrase}")

    compile(acceptance_collector, str(ACCEPTANCE_COLLECTOR), "exec")
    for token in (
        "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        '"runtime_evidence_status": "passed" if runtime_passed else "failed"',
        '"production_runtime_acceptance": "unaccepted"',
        '"application_consumer_integration"',
        '"quarantine_execution_evidence"',
        'error_finding.result == "unknown"',
        'clean_finding.result == "clean"',
        'eicar_finding.result == "malicious"',
        '"protection_claim_authority": False',
    ):
        require(token in acceptance_collector, f"acceptance collector missing invariant: {token}")

    for token in (
        "workflow_dispatch:",
        "expected_sha:",
        "environment: wardveil-production",
        "WARDVEIL_VPS_HOST: ${{ secrets.WARDVEIL_VPS_HOST }}",
        "WARDVEIL_VPS_USER: ${{ secrets.WARDVEIL_VPS_USER }}",
        "WARDVEIL_VPS_SSH_PRIVATE_KEY: ${{ secrets.WARDVEIL_VPS_SSH_PRIVATE_KEY }}",
        "WARDVEIL_VPS_SSH_HOST_KEY: ${{ secrets.WARDVEIL_VPS_SSH_HOST_KEY }}",
        "StrictHostKeyChecking=yes",
        "ssh-keygen -F",
        "persist-credentials: false",
        "/opt/goreecloud/wardveil/clamav",
        "collect_wardveil_clamav_acceptance.py",
        "production_runtime_acceptance",
        "sudo docker compose",
        "ln -sfn",
    ):
        require(token in deployment_workflow, f"production deployment workflow missing invariant: {token}")
    for forbidden in (
        "StrictHostKeyChecking=no",
        "ssh-keyscan",
        "appleboy/ssh-action",
        "0.0.0.0:3310",
        "network_mode: host",
    ):
        require(forbidden not in deployment_workflow, f"production deployment workflow contains unsafe pattern: {forbidden}")

    validate_mail_consumer_source_evidence()
    validate_drive_consumer_source_evidence()
    validate_browser_consumer_source_evidence()
    validate_ai_consumer_source_evidence()
    print("Wardveil ClamAV runtime health and deployment validation passed.")


if __name__ == "__main__":
    main()
