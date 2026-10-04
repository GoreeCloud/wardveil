#!/usr/bin/env python3
from pathlib import Path
import json
import re

ROOT = Path(__file__).resolve().parents[1]
workflow = (ROOT / ".github/workflows/deploy-cloudflare-persistence.yml").read_text()
runner_config_text = (ROOT / "cloudflare" / "acceptance-runner" / "wrangler.jsonc").read_text()
runner_source = (ROOT / "cloudflare" / "acceptance-runner" / "src" / "index.ts").read_text()
doc = (ROOT / "docs/CLOUDFLARE-RUNTIME-EVIDENCE-COLLECTION.md").read_text()
runtime_contract = json.loads((ROOT / "contracts" / "wardveil.cloudflare.runtime-acceptance.json").read_text())

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
assert runtime_contract.get("evidence_validity_seconds") == 3600, "runtime evidence validity policy drifted"

for token in [
    'url.pathname === "/healthz"',
    '"/observe-failure"',
    'request.method !== "POST"',
    'WARDVEIL_ACCEPTANCE_PROBE.runAcceptance(body.revision)',
    'WARDVEIL_ACCEPTANCE_PROBE.runObservabilityFailure(body.revision, body.marker)',
    '/^[0-9a-f]{40}$/.test(value)',
]:
    assert token in runner_source, f"missing acceptance runner invariant: {token}"

for token in [
    "workflow_dispatch:",
    "environment: wardveil-production",
    "persist-credentials: false",
    "wrangler@4.37.0",
    "Deploy Wardveil persistence Worker",
    "Deploy internal Wardveil acceptance probe",
    "--var EXPECTED_REVISION:$WARDVEIL_CANDIDATE_SHA",
    "--var ACCEPTANCE_TENANT:wardveil-runtime-acceptance",
    "acceptance-runner/wrangler.jsonc",
    "Collect privileged service-binding and retention evidence",
    "Collect bounded observability failure evidence",
    "wrangler tail goreecloud-wardveil-persistence --format json --search",
    "/observe-failure",
    "authorized_append_read",
    "duplicate_record_rejection",
    "checkpoint_non_regression",
    "payload_digest_verification",
    "pitr_availability",
    "retention_alarm_evidence",
    "restore_verification_exercise",
    "observability_failure_evidence",
    "public_mutation_surface_absent",
    "'workflow_control_revision': workflow_control_sha",
    "'acceptance_status': 'unaccepted'",
    "'valid_until': expiry",
    "evidence_validity_seconds",
    "datetime.timedelta(seconds=validity_seconds)",
    "storage_health_is_protection_claim",
    "everkeep_recovery_authority_preserved",
]:
    assert token in workflow, f"missing runtime evidence workflow invariant: {token}"

assert "actions/upload-artifact@" not in workflow, "runtime evidence must not add an ungoverned artifact Action dependency"
assert "contents: write" not in workflow, "runtime evidence collection must not gain repository write permission"
assert "curl --silent --show-error --output /tmp/wardveil-probe.json" in workflow
assert "test \"$code\" = \"200\"" in workflow
assert "Generic public POST /records" in workflow or "public POST /records" in doc
assert "Remaining pending acceptance evidence: Everkeep-governed restore verification" in workflow

for phrase in [
    "PITR availability is not restore verification.",
    "Deployment success is not runtime acceptance.",
    "Storage health is not evidence",
    "acceptance_status: unaccepted",
    "Everkeep remains the resilience, backup, restore, and recovery-verification authority.",
    "No evidence-collection workflow may manufacture, extend, reinterpret, or upgrade security state",
    "Producer-declared freshness",
    "3600 seconds",
    "must not extend or replace the deadline",
]:
    assert phrase in doc, f"missing evidence-collection authority boundary: {phrase}"

print("Wardveil Cloudflare runtime evidence collection validation passed.")
