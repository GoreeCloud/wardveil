#!/usr/bin/env python3
from pathlib import Path
import json
import re

ROOT = Path(__file__).resolve().parents[1]
workflow = (ROOT / ".github" / "workflows" / "deploy-cloudflare-persistence.yml").read_text()
runner_config_text = (ROOT / "cloudflare" / "acceptance-runner" / "wrangler.jsonc").read_text()
runner_source = (ROOT / "cloudflare" / "acceptance-runner" / "src" / "index.ts").read_text()
doc = (ROOT / "CLOUDFLARE-RUNTIME-EVIDENCE-COLLECTION.md").read_text()

runner_config = json.loads(re.sub(r"//.*", "", runner_config_text))
assert runner_config["name"] == "goreecloud-wardveil-acceptance-runner"
assert runner_config["compatibility_date"] == "2026-08-26"
assert runner_config["services"] == [{
    "binding": "WARDVEIL_ACCEPTANCE_PROBE",
    "service": "goreecloud-wardveil-acceptance-probe",
    "remote": True,
}]
assert "workers_dev" not in runner_config, "local-only runner must not gain a deploy/public configuration"
assert "routes" not in runner_config, "local-only runner must not gain routes"

for token in [
    'url.pathname === "/healthz"',
    'url.pathname !== "/run"',
    'request.method !== "POST"',
    'WARDVEIL_ACCEPTANCE_PROBE.runAcceptance(revision)',
    '/^[0-9a-f]{40}$/.test(revision)',
]:
    assert token in runner_source, f"missing acceptance runner invariant: {token}"

for token in [
    "workflow_dispatch:",
    "environment: wardveil-production",
    "persist-credentials: false",
    "wrangler@4.37.0",
    "Deploy Wardveil persistence Worker",
    "Deploy internal Wardveil acceptance probe",
    "--var EXPECTED_REVISION:$GITHUB_SHA",
    "--var ACCEPTANCE_TENANT:wardveil-runtime-acceptance",
    "acceptance-runner/wrangler.jsonc",
    "Collect privileged service-binding evidence",
    "authorized_append_read",
    "duplicate_record_rejection",
    "checkpoint_non_regression",
    "payload_digest_verification",
    "pitr_availability",
    "retention_alarm_evidence",
    "restore_verification_exercise",
    "observability_failure_evidence",
    "public_mutation_surface_absent",
    "'acceptance_status': 'unaccepted'",
    "storage_health_is_protection_claim",
    "everkeep_recovery_authority_preserved",
]:
    assert token in workflow, f"missing runtime evidence workflow invariant: {token}"

assert "actions/upload-artifact@" not in workflow, "runtime evidence must not add an ungoverned artifact Action dependency"
assert "contents: write" not in workflow, "runtime evidence collection must not gain repository write permission"
assert "curl --silent --show-error --output /tmp/wardveil-probe.json" in workflow
assert "test \"$code\" = \"200\"" in workflow
assert "Generic public POST /records" in workflow or "public POST /records" in doc

for phrase in [
    "PITR availability is not restore verification.",
    "Deployment success is not runtime acceptance.",
    "Storage health is not evidence",
    "acceptance_status: unaccepted",
    "Everkeep remains the resilience, backup, restore, and recovery-verification authority.",
    "No evidence-collection workflow may manufacture, extend, reinterpret, or upgrade security state",
]:
    assert phrase in doc, f"missing evidence-collection authority boundary: {phrase}"

print("Wardveil Cloudflare runtime evidence collection validation passed.")
