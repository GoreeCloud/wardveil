#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "reference/wardveil_platform_policy_v1.py").read_text()
doc = (ROOT / "PLATFORM-POLICY-INTEGRATION.md").read_text()
workflow = (ROOT / ".github/workflows/validate.yml").read_text()

required = [
    'POLICY_CONTRACT_REVISION = "46071886da37a6566b69cc923005eef64cce2bcc"',
    '"execution_authority": False',
    '"protection_authority": False',
    '"production_accepted": False',
]
for item in required:
    assert item in source, item
for item in [
    "GoreeCloud Policy does not replace Wardveil security-domain policy semantics.",
    "A Policy allow is not Wardveil execution authorization.",
    "Source adoption does not establish live Policy runtime acceptance.",
]:
    assert item in doc, item
assert "Test GoreeCloud Policy v1 source adapter" in workflow
assert "Validate GoreeCloud Policy v1 source adapter" in workflow
print("Wardveil GoreeCloud Policy v1 source adapter validation: PASS")
