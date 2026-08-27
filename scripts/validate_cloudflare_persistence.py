#!/usr/bin/env python3
from pathlib import Path
import json
import re

ROOT = Path(__file__).resolve().parents[1]
config_text = (ROOT / "cloudflare" / "wrangler.jsonc").read_text()
source = (ROOT / "cloudflare" / "src" / "index.ts").read_text()
doc = (ROOT / "CLOUDFLARE-PERSISTENCE.md").read_text()
execution_doc = (ROOT / "EXECUTION-STATE.md").read_text()
execution_contract = json.loads((ROOT / "contracts" / "wardveil.execution-state.json").read_text())
package = json.loads((ROOT / "cloudflare" / "package.json").read_text())

# Strip the schema-free JSONC surface used by this file so the config remains machine-checkable here.
config = json.loads(re.sub(r"//.*", "", config_text))
assert config["compatibility_date"] == "2026-08-26"
assert "nodejs_compat" in config.get("compatibility_flags", [])
assert config["durable_objects"]["bindings"] == [{"name": "WARDVEIL_PERSISTENCE", "class_name": "WardveilPersistenceDO"}]
assert config["migrations"] == [{"tag": "v1", "new_sqlite_classes": ["WardveilPersistenceDO"]}]
assert config["observability"]["enabled"] is True

required_source = [
    "extends DurableObject<Bindings>",
    "transactionSync",
    "CREATE TABLE IF NOT EXISTS wardveil_records",
    "record_id TEXT NOT NULL UNIQUE",
    "consumer_checkpoints",
    "checkpoint_regression",
    "maintenance_evidence",
    "CREATE TABLE IF NOT EXISTS execution_authorization_claims",
    "UNIQUE(executor_id, idempotency_key)",
    "CREATE TABLE IF NOT EXISTS execution_receipts",
    "authorization_nonce_conflict",
    "executor_idempotency_conflict",
    "execution_reconciliation_required",
    "execution_receipt_conflict",
    "claimExecutionAuthorization",
    "finalizeExecutionAuthorization",
    "getExecutionReceipt",
    "setAlarm",
    "getCurrentBookmark",
    "databaseSize",
    'encryption_at_rest: "cloudflare_managed"',
    'replay_storage: "durable_object_sqlite"',
    'receipt_storage: "durable_object_sqlite"',
    'uncertain_outcome_behavior: "reconciliation_required"',
    "security_state_authority: false",
    "protection_claim_authority: false",
    'mutation_api: "service-binding-rpc-only"',
]
for token in required_source:
    assert token in source, f"missing Cloudflare persistence invariant: {token}"

assert "Math.random(" not in source
assert "passThroughOnException" not in source
for forbidden_public_auth in (
    'headers.get("Authorization")',
    "headers.get('Authorization')",
    'headers.get("authorization")',
    "headers.get('authorization')",
    'startsWith("Bearer ")',
    "startsWith('Bearer ')",
):
    assert forbidden_public_auth not in source, "public bearer-token mutation surface must not be introduced by this adapter"
assert 'url.pathname === "/healthz"' in source
assert 'return new Response("Not Found", { status: 404 })' in source

for phrase in [
    "Persistence is not a security-state authority.",
    "storage operational` is not equivalent to `Protected by Wardveil`",
    "service-binding/RPC-first",
    "production deployment",
    "Privacy Shield minimization review",
    "Everkeep recovery coordination",
]:
    assert phrase in doc, f"missing Cloudflare persistence documentation boundary: {phrase}"

for phrase in [
    "execution_reconciliation_required",
    "automatic blind re-execution is prohibited",
    "Persistence is not a security-state authority.",
    "service-binding-only execution-state storage",
    "production status remains `unaccepted`",
]:
    assert phrase in execution_doc, f"missing execution-state documentation boundary: {phrase}"

assert execution_contract["cloudflare_reference"]["backend"] == "Durable Object SQLite"
assert execution_contract["cloudflare_reference"]["public_mutation_api_allowed"] is False
assert execution_contract["cloudflare_reference"]["service_binding_rpc_only"] is True
assert execution_contract["claim"]["blind_reexecution_after_uncertain_outcome_allowed"] is False
assert execution_contract["production_runtime_status"] == "unaccepted"

assert package["private"] is True
assert package["scripts"]["types"] == "wrangler types"
assert package["scripts"]["check"] == "tsc --noEmit"

print("Wardveil Cloudflare persistence adapter validation passed.")
