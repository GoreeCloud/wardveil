#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "reference/wardveil_observability_v1.py").read_text()
doc = (ROOT / "docs/OBSERVABILITY-INTEGRATION.md").read_text()
workflow = (ROOT / ".github/workflows/validate.yml").read_text()

for item in [
    'OBSERVABILITY_CONTRACT_REVISION = "a7f6a65f442d3e517baddbe7b6ce7c250d142c8c"',
    '"goreecloud-wardveil-security"',
    "healthy_signal_cannot_claim_collection_gaps",
]:
    assert item in source, item
for item in [
    "Operational signals are evidence, not protection authority.",
    "Raw private content and reusable credentials are excluded.",
    "Source adoption does not establish live Observability acceptance.",
]:
    assert item in doc, item
assert "Test GoreeCloud Observability v1 source adapter" in workflow
assert "Validate GoreeCloud Observability v1 source adapter" in workflow
print("Wardveil GoreeCloud Observability v1 source adapter validation: PASS")
