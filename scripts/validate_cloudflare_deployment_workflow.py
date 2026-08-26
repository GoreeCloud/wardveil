#!/usr/bin/env python3
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
workflow = (ROOT / ".github/workflows/deploy-cloudflare-persistence.yml").read_text()
ops = (ROOT / "CLOUDFLARE-RUNTIME-OPERATIONS.md").read_text()
contract = json.loads((ROOT / "contracts/wardveil.cloudflare.deployment.json").read_text())
acceptance = json.loads((ROOT / "contracts/wardveil.cloudflare.runtime-acceptance.json").read_text())
wrangler = (ROOT / "cloudflare/wrangler.jsonc").read_text()

required = {
    "schema_version": 2,
    "worker_name": "goreecloud-wardveil-persistence",
    "acceptance_probe_worker_name": "goreecloud-wardveil-acceptance-probe",
    "wrangler_version": "4.37.0",
    "deployment_trigger": "manual workflow_dispatch",
    "required_branch": "main",
    "required_environment": "wardveil-production",
    "exact_revision_required": True,
    "public_health_path": "/healthz",
    "generic_public_mutation_path": "/records",
    "generic_public_mutation_allowed": False,
    "service_binding_required_for_privileged_operations": True,
    "acceptance_probe_public_route_allowed": False,
    "remote_service_binding_evidence_collection": True,
    "deployment_success_is_runtime_acceptance": False,
    "health_success_is_protection_claim": False,
    "storage_health_is_protection_claim": False,
    "production_runtime_status_source": "contracts/wardveil.cloudflare.runtime-acceptance.json",
}
for key, expected in required.items():
    if contract.get(key) != expected:
        raise SystemExit(f"Cloudflare deployment contract mismatch: {key}")

if set(contract.get("required_secrets", [])) != {
    "CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID", "WARDVEIL_HEALTH_URL"
}:
    raise SystemExit("Cloudflare deployment secret contract drifted")

for token in [
    "workflow_dispatch:",
    "expected_sha:",
    "if: github.ref == 'refs/heads/main'",
    "runs-on: ubuntu-24.04",
    "environment: wardveil-production",
    "CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}",
    "CLOUDFLARE_ACCOUNT_ID: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}",
    "WARDVEIL_HEALTH_URL: ${{ secrets.WARDVEIL_HEALTH_URL }}",
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "persist-credentials: false",
    'test "$GITHUB_SHA" = "$EXPECTED_SHA"',
    'test "$(git rev-parse HEAD)" = "$EXPECTED_SHA"',
    "wrangler@4.37.0",
    "npx wrangler deploy --config wrangler.jsonc",
    "Deploy internal Wardveil acceptance probe",
    "--var EXPECTED_REVISION:$GITHUB_SHA",
    "acceptance-runner/wrangler.jsonc",
    "Collect privileged service-binding and retention evidence",
    "Collect bounded observability failure evidence",
    "wrangler tail goreecloud-wardveil-persistence --format json --search",
    "curl --fail-with-body",
    "POST \"$origin/records\"",
    "404|405",
    "Remaining pending acceptance evidence: Everkeep-governed restore verification",
    "Runtime acceptance status: **unaccepted**",
]:
    if token not in workflow:
        raise SystemExit(f"Cloudflare deployment workflow missing: {token}")

if "contents: read" not in workflow:
    raise SystemExit("Deployment workflow must retain least-privilege contents: read")
if "contents: write" in workflow:
    raise SystemExit("Deployment workflow may not gain repository write permission")
if "ubuntu-latest" in workflow:
    raise SystemExit("Deployment workflow may not use moving ubuntu-latest runner")
if "@v" in workflow:
    raise SystemExit("Deployment workflow may not use mutable GitHub Action major tags")

for phrase in [
    "Storage health does not create or upgrade",
    "PITR availability is not restore verification",
    "Secrets must not be committed",
    "No workflow may set `production_runtime_status` to accepted solely because deployment or health checks succeed.",
    "Privileged acceptance should be performed from an explicitly authorized GoreeCloud service binding",
    "production_runtime_status = unaccepted",
]:
    if phrase.lower() not in ops.lower():
        raise SystemExit(f"Cloudflare runtime operations boundary missing: {phrase}")

if acceptance.get("production_runtime_status") != "unaccepted":
    raise SystemExit("Deployment workflow source must not silently mark production runtime accepted")
if contract.get("worker_name") != acceptance.get("worker_name"):
    raise SystemExit("Deployment and runtime-acceptance worker names must match")
if '"name": "goreecloud-wardveil-persistence"' not in wrangler:
    raise SystemExit("Wrangler worker name drifted from deployment contract")

print("Wardveil Cloudflare deployment workflow validation passed.")
