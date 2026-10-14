#!/usr/bin/env python3
"""Assert historical Cloudflare evidence never reuses deployment identity or promotes Seal."""
from pathlib import Path

root = Path(__file__).resolve().parents[1]
workflow = (root / ".github/workflows/verify-cloudflare-historical-observability.yml").read_text()
script = (root / "scripts/verify_cloudflare_historical_observability.py").read_text()
docs = (root / "docs/CLOUDFLARE-RUNTIME-EVIDENCE-COLLECTION.md").read_text()

for token in [
    "workflow_dispatch:",
    "if: github.ref == 'refs/heads/main'",
    "environment: wardveil-production",
    "permissions:\n  contents: read",
    "CLOUDFLARE_OBSERVABILITY_API_TOKEN: ${{ secrets.CLOUDFLARE_OBSERVABILITY_API_TOKEN }}",
    "CLOUDFLARE_ACCOUNT_ID: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}",
    "persist-credentials: false",
    "verify_cloudflare_historical_observability.py --self-test",
    "verify_cloudflare_historical_observability.py",
]:
    assert token in workflow, f"Missing guarded historical readback configuration: {token}"

for forbidden in [
    "secrets.CLOUDFLARE_API_TOKEN",
    "wrangler deploy",
    "actions/upload-artifact",
    "contents: write",
    "pull_request:",
]:
    assert forbidden not in workflow, f"Forbidden historical readback capability: {forbidden}"

for token in [
    'os.environ.get("CLOUDFLARE_OBSERVABILITY_API_TOKEN"',
    '"datasets": ["cloudflare-workers"]',
    '"dry": True',
    '"limit": 25',
    'events = events_obj["events"]',
    'run.get("status") == "COMPLETED"',
    'matching_producer(e, marker)',
    '"acceptance_authority": False',
]:
    assert token in script, f"Missing nonpromoting Cloudflare verifier invariant: {token}"
assert 'os.environ["CLOUDFLARE_API_TOKEN"]' not in script
assert "Workers Observability Write" in docs
assert "CLOUDFLARE_OBSERVABILITY_API_TOKEN" in docs
assert "HTTP **403**" in docs
print("Wardveil historical observability credential isolation validation passed.")
