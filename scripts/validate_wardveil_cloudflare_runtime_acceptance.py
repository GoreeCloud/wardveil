#!/usr/bin/env python3
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
contract = json.loads((ROOT / "contracts/wardveil.cloudflare.runtime-acceptance.json").read_text())
doc = (ROOT / "CLOUDFLARE-DEPLOYMENT.md").read_text()
wrangler = (ROOT / "cloudflare/wrangler.jsonc").read_text()
source = (ROOT / "cloudflare/src/index.ts").read_text()

required = {
    "worker_name": "goreecloud-wardveil-persistence",
    "durable_object_binding": "WARDVEIL_PERSISTENCE",
    "durable_object_class": "WardveilPersistenceDO",
    "storage_engine": "sqlite-backed durable object",
    "mutation_surface": "authenticated service binding / RPC",
    "evidence_validity_seconds": 3600,
    "storage_health_is_protection_claim": False,
    "pitr_availability_is_restore_verification": False,
    "cloudflare_authority_transferred_to_security_state": False,
    "everkeep_recovery_authority_preserved": True,
    "production_runtime_status": "unaccepted",
}
for key, expected in required.items():
    if contract.get(key) != expected:
        raise SystemExit(f"Cloudflare acceptance contract mismatch: {key}")

if contract.get("public_http_surface") != ["/healthz", "/readyz"]:
    raise SystemExit("Public HTTP surface must remain bounded to liveness/readiness only")

expected_evidence = {
    "deployed_revision_match", "health_endpoint", "readiness_endpoint", "authorized_append_read",
    "duplicate_record_rejection", "checkpoint_non_regression",
    "retention_alarm_evidence", "payload_digest_verification",
    "pitr_availability", "restore_verification_exercise",
    "observability_failure_evidence", "public_mutation_surface_absent",
}
if set(contract.get("required_acceptance_evidence", [])) != expected_evidence:
    raise SystemExit("Runtime acceptance evidence set drifted")

for token in [
    '"name": "goreecloud-wardveil-persistence"',
    '"name": "WARDVEIL_PERSISTENCE"',
    '"class_name": "WardveilPersistenceDO"',
    '"new_sqlite_classes": ["WardveilPersistenceDO"]',
    '"observability"',
]:
    if token not in wrangler:
        raise SystemExit(f"Wrangler deployment contract missing: {token}")

if "/healthz" not in source or "/readyz" not in source:
    raise SystemExit("Cloudflare Worker must retain /healthz and /readyz")

for phrase in [
    "storage health",
    "protected by Wardveil",
    "PITR availability is not restore verification",
    "production runtime status remains **unaccepted**",
]:
    if phrase.lower() not in doc.lower():
        raise SystemExit(f"Deployment boundary documentation missing: {phrase}")

print("Wardveil Cloudflare runtime acceptance contract: OK")
