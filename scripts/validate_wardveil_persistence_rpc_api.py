#!/usr/bin/env python3
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "wardveil.persistence-rpc.v1.json"
SOURCE = ROOT / "cloudflare" / "src" / "index.ts"
MANIFEST = ROOT / "goreecloud.platform.yaml"
DOC = ROOT / "PERSISTENCE-RPC-API.md"

def require(condition, message):
    if not condition:
        raise SystemExit(message)

def main():
    contract=json.loads(CONTRACT.read_text())
    source=SOURCE.read_text()
    manifest=MANIFEST.read_text()
    doc=DOC.read_text()

    require(contract["version"] == "wardveil-persistence-rpc/v1", "unexpected RPC API version")
    require(contract["transport"] == "cloudflare-service-binding-rpc", "unexpected RPC transport")
    require(contract["binding"] == "WARDVEIL_PERSISTENCE", "unexpected RPC binding")
    require(contract["public_http_surface"] == ["/healthz", "/readyz"], "public HTTP surface drift")

    required_ops={
        "append","readAfter","checkpoint","getCheckpoint",
        "claimExecutionAuthorization","finalizeExecutionAuthorization",
        "getExecutionReceipt","maintenanceEvidence","health",
    }
    require(set(contract["operations"]) == required_ops, "RPC operation set drift")
    for op in required_ops | {"scheduleAcceptanceRetentionAlarm","emitAcceptanceObservabilityFailure"}:
        require(f"async {op}(" in source, f"runtime missing RPC operation: {op}")

    authority=contract["authority"]
    for field in (
        "caller_authentication_required",
        "public_mutation_allowed",
        "security_state_authority_transferred",
        "protection_claim_authority_transferred",
        "recovery_authority_transferred",
    ):
        require(field in authority, f"authority field missing: {field}")
    require(authority["caller_authentication_required"] is True, "RPC callers must be authenticated")
    for field in (
        "public_mutation_allowed",
        "security_state_authority_transferred",
        "protection_claim_authority_transferred",
        "recovery_authority_transferred",
    ):
        require(authority[field] is False, f"authority must remain false: {field}")

    require("wardveil-persistence-rpc/v1" in manifest, "Platform Contract missing RPC API version")
    require("service-binding:WARDVEIL_PERSISTENCE" in manifest, "Platform Contract missing RPC endpoint")
    require("generic public record, checkpoint, execution, or acceptance mutation route is prohibited" in doc, "documentation missing public-mutation prohibition")
    print("Wardveil persistence RPC API v1 validation passed")

if __name__ == "__main__":
    main()
