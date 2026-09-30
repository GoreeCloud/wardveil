#!/usr/bin/env python3
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]
contract = json.loads((ROOT / "contracts" / "wardveil.platform-api.v1.json").read_text())
source = (ROOT / "cloudflare" / "src" / "index.ts").read_text()
manifest = (ROOT / "goreecloud.platform.yaml").read_text()
doc = (ROOT / "PLATFORM-API.md").read_text()

expected_methods = [
    "append", "readAfter", "checkpoint", "getCheckpoint",
    "claimExecutionAuthorization", "finalizeExecutionAuthorization",
    "getExecutionReceipt", "health", "maintenanceEvidence",
]
acceptance_only = ["scheduleAcceptanceRetentionAlarm", "emitAcceptanceObservabilityFailure"]

assert contract["schema_version"] == 1
assert contract["contract_id"] == "goreecloud.wardveil.platform-api.v1"
assert contract["api_version"] == "wardveil-persistence-rpc/v1"
assert contract["transport"] == "cloudflare-worker-service-binding-rpc"
assert contract["service_name"] == "goreecloud-wardveil-persistence"
assert contract["endpoint_reference"] == "service-binding://goreecloud-wardveil-persistence"
assert contract["public_http_surface"] == ["/healthz", "/readyz"]
assert contract["application_rpc_methods"] == expected_methods
assert contract["acceptance_only_rpc_methods"] == acceptance_only
assert contract["production_acceptance_status"] == "unaccepted"

authority = contract["authority"]
assert authority == {
    "authenticated_service_binding_required_for_privileged_operations": True,
    "public_mutation_api_allowed": False,
    "persistence_is_security_state_authority": False,
    "api_use_is_execution_authority": False,
    "api_use_is_protection_claim": False,
    "authority_transfer": False,
}

for method in expected_methods + acceptance_only:
    assert f"async {method}(" in source, method
for route in ["/healthz", "/readyz"]:
    assert f'url.pathname === "{route}"' in source, route
assert 'return new Response("Not Found", { status: 404 })' in source

for token in [
    "wardveil-persistence-rpc/v1",
    "service-binding://goreecloud-wardveil-persistence",
    "Authenticated internal Worker service-binding/RPC access",
]:
    assert token in manifest, token

for phrase in [
    "This is a symbolic private service-binding reference, not a public Internet URL.",
    "There is no generic public mutation API.",
    "An authenticated API call does not create Wardveil execution authority",
    "production API acceptance remains **unaccepted**",
]:
    assert phrase in doc, phrase

print("Wardveil private platform API V1 validation: PASS")
