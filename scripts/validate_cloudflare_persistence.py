#!/usr/bin/env python3
from pathlib import Path
import json
import re

ROOT = Path(__file__).resolve().parents[1]
config_text = (ROOT / "cloudflare" / "wrangler.jsonc").read_text()
source = (ROOT / "cloudflare" / "src" / "index.ts").read_text()
doc = (ROOT / "CLOUDFLARE-PERSISTENCE.md").read_text()
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
    "setAlarm",
    "getCurrentBookmark",
    "databaseSize",
    'encryption_at_rest: "cloudflare_managed"',
    "security_state_authority: false",
    "protection_claim_authority: false",
    'mutation_api: "service-binding-rpc-only"',
]
for token in required_source:
    assert token in source, f"missing Cloudflare persistence invariant: {token}"

assert "Math.random(" not in source
assert "passThroughOnException" not in source
assert "Authorization" not in source, "public bearer-token mutation surface must not be introduced by this adapter"
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

assert package["private"] is True
assert package["scripts"]["types"] == "wrangler types"
assert package["scripts"]["check"] == "tsc --noEmit"

print("Wardveil Cloudflare persistence adapter validation passed.")
