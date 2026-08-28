#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "wardveil.scan-service-transport.json"
REFERENCE = ROOT / "reference" / "wardveil_scan_transport.py"
SERVER = ROOT / "deployment" / "scan-service" / "server.py"
UNIT = ROOT / "deployment" / "scan-service" / "wardveil-scan.service"
ENV_EXAMPLE = ROOT / "deployment" / "scan-service" / ".env.example"
PROBE = ROOT / "scripts" / "probe_wardveil_scan_service.py"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> None:
    for path in (CONTRACT, REFERENCE, SERVER, UNIT, ENV_EXAMPLE, PROBE):
        require(path.is_file(), f"missing Wardveil Scan transport file: {path.relative_to(ROOT)}")

    contract = json.loads(CONTRACT.read_text())
    reference = REFERENCE.read_text()
    server = SERVER.read_text()
    unit = UNIT.read_text()
    env_example = ENV_EXAMPLE.read_text()
    probe = PROBE.read_text()

    require(contract.get("contract_version") == "0.1.0", "unexpected scan transport contract version")
    require(contract.get("foundation_version") == "0.9.0", "scan transport foundation version mismatch")
    endpoint = contract.get("endpoint") or {}
    require(endpoint.get("path") == "/v1/scan", "unexpected scan endpoint")
    require(endpoint.get("default_bind") == "127.0.0.1:8788", "scan service must default to loopback")
    require(endpoint.get("public_anonymous_access_allowed") is False, "anonymous scan access must remain forbidden")
    require(endpoint.get("direct_clamav_access_allowed") is False, "applications must not access ClamAV directly")

    auth = contract.get("request_authentication") or {}
    for key in (
        "signature_binds_all_required_fields_except_signature",
        "signature_binds_body_digest",
        "constant_time_verification_required",
        "caller_resource_type_allowlist_required",
        "unknown_caller_fails_closed",
        "unknown_key_fails_closed",
        "digest_mismatch_fails_closed",
        "expired_or_future_request_fails_closed",
        "conflicting_nonce_reuse_fails_closed",
    ):
        require(auth.get(key) is True, f"scan authentication invariant must be true: {key}")
    require(auth.get("production_signature_scheme_accepted") is False, "reference HMAC transport must not be production-accepted")

    response = contract.get("response") or {}
    require(response.get("shape") == "consumer_scan_envelope", "scan response must use consumer envelope")
    require(response.get("result_field") == "result", "consumer scan record must use result field")
    require(response.get("evidence_refs_required_for_clean") is True, "clean scan must carry evidence")

    health = contract.get("scanner_health") or {}
    require(health.get("clean_requires_current_acceptable_health") is True, "clean must require current health")
    require(health.get("clean_includes_scanner_health_evidence_ref") is True, "clean must reference scanner health")
    require(health.get("malicious_exact_digest_remains_actionable_when_health_degraded") is True, "malicious must remain actionable")

    require(contract.get("production_runtime_status") == "unaccepted", "scan transport source must remain runtime-unaccepted")
    remaining = set(contract.get("remaining_acceptance_requirements") or [])
    for requirement in (
        "approved production service authentication and key management",
        "at least one deployed application consumer using authenticated Wardveil Scan transport",
        "authorized quarantine execution evidence",
    ):
        require(requirement in remaining, f"missing scan transport acceptance requirement: {requirement}")

    for token in (
        "canonical_auth_material",
        "hmac.compare_digest",
        "scan_content_digest_mismatch",
        "scan_resource_type_not_authorized",
        "scan_request_timestamp_outside_window",
        "scan_nonce_conflict",
        "resource_digest_sha256",
        '"result": finding.result',
        "health.evidence_ref",
    ):
        require(token in reference, f"missing scan transport implementation invariant: {token}")

    require('WARDVEIL_SCAN_CALLERS_JSON' in server, "scan server must require caller credentials")
    require('WARDVEIL_SCAN_BIND", "127.0.0.1:8788"' in server, "scan server must default to loopback")
    require("non-loopback scan bind requires" in server, "scan server must fail closed on non-loopback bind")
    require("log_message" in server and "return" in server, "scan server must suppress metadata-bearing default logs")
    require("/v1/scan" in server and "/healthz" in server, "scan server routes missing")
    require("X-Wardveil-Signature" in server, "scan server signature header missing")

    require("User=wardveil-scan" in unit, "scan service must run as dedicated user")
    require("NoNewPrivileges=true" in unit, "scan systemd unit must enable no-new-privileges")
    require("CapabilityBoundingSet=" in unit, "scan systemd unit must drop capabilities")
    require("ProtectSystem=strict" in unit, "scan systemd unit must protect system filesystem")

    require("WARDVEIL_SCAN_CALLERS_JSON=[]" in env_example, "example must not contain caller secret material")
    serialized = (reference + server + unit + env_example + probe).lower()
    for forbidden in ("access_token=", "password=", "private_key", "authorization: bearer"):
        require(forbidden not in serialized, f"potential secret material found in scan transport source: {forbidden}")

    require("EICAR" in probe and "clean_control" in probe, "runtime probe must cover clean and EICAR")
    require('"application_consumer_integration": "not_proven_by_probe"' in probe, "probe must not overclaim app integration")

    print("Wardveil Scan authenticated transport validation passed")


if __name__ == "__main__":
    main()
