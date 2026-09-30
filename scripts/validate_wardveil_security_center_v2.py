#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "contracts" / "wardveil.security-center.v2.schema.json"
DOC = ROOT / "docs/SECURITY-CENTER-V2.md"
REFERENCE = ROOT / "reference" / "wardveil_security_center_v2.py"
ROADMAP = ROOT / "docs/PLANNED-FEATURES.md"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
doc = DOC.read_text(encoding="utf-8")
reference = REFERENCE.read_text(encoding="utf-8")
roadmap = ROADMAP.read_text(encoding="utf-8")

require(schema.get("title") == "Wardveil Security Center 2.0 View Model", "unexpected Security Center schema title")
require(schema.get("additionalProperties") is False, "Security Center top-level schema must reject extension fields")
require(schema["properties"]["schema_version"].get("const") == "0.2.0", "Security Center schema version must be 0.2.0")
require(schema["properties"]["presentation"]["properties"]["glaze_ui_version"].get("const") == "1.3.0", "Security Center must target GLAZE UI 1.3.0 Stable")
require(schema["properties"]["presentation"]["properties"]["glaze_ui_revision"].get("const") == "8354308445da9ac35ced2b37a7f503a08a0aaf72", "Security Center must pin the reviewed GLAZE UI V1.3 authority revision")
require(schema["properties"]["presentation"]["properties"]["rollback_version"].get("const") == "1.2.0", "Security Center must preserve V1.2 rollback provenance")

expected_areas = {
    "protection",
    "protection_coverage",
    "threats",
    "quarantine",
    "incidents",
    "sessions_and_devices",
    "application_access",
    "security_policies",
    "recommendations",
    "security_evidence",
    "audit_history",
    "recovery_verification",
}
area_enum = set(schema["properties"]["areas"]["items"]["enum"])
require(area_enum == expected_areas, "Security Center primary-area contract drifted")
require(schema["properties"]["areas"].get("minItems") == 12 and schema["properties"]["areas"].get("maxItems") == 12, "Security Center must expose the complete twelve-area information architecture")

require("privacy_minimization" in schema.get("required", []), "Security Center must require privacy minimization metadata")
privacy = schema["properties"]["privacy_minimization"]
require(privacy.get("additionalProperties") is False, "privacy minimization contract must reject extension fields")
for field in (
    "raw_private_content_included",
    "raw_private_activity_included",
    "reusable_credentials_included",
    "recovery_material_included",
    "unrestricted_diagnostic_payloads_included",
):
    require(privacy["properties"][field].get("const") is False, f"{field} must be fixed false")
require(privacy["properties"]["identifier_scope"].get("const") == "necessary_bounded", "identifier scope must remain necessary_bounded")
require(privacy["properties"]["privacy_shield_review_required"].get("const") is True, "Privacy Shield review requirement must remain explicit")

for needle in (
    "Wardveil Security Center 2.0",
    "GLAZE UI V1.3 / 1.3.0 Stable",
    "8354308445da9ac35ced2b37a7f503a08a0aaf72",
    "GLAZE UI V1.2 / 1.2.0",
    "Why this status?",
    "Protected",
    "Reconciliation Required",
    "Light",
    "Dark",
    "Deep Dark",
    "Reduced Transparency",
    "Reduced Motion",
    "Increased Contrast",
    "Forced Colors",
    "Touch Assistance",
    "rendered visual review",
    "deployment verification",
    "rollback verification",
    "Presentation is not authority",
    "source validation only",
    "Administrative privacy-minimization contract",
    "raw_private_content_included",
    "necessary_bounded",
    "privacy_shield_review_required",
):
    require(needle in doc, f"Security Center 2.0 documentation missing invariant: {needle}")

for needle in (
    'SCHEMA_VERSION = "0.2.0"',
    'GLAZE_UI_VERSION = "1.3.0"',
    'GLAZE_UI_REVISION = "8354308445da9ac35ced2b37a7f503a08a0aaf72"',
    'GLAZE_UI_ROLLBACK_VERSION = "1.2.0"',
    '"security_center_protection_claim_unproven"',
    '"security_center_execution_uncertainty"',
    '"security_center_evidence_expired"',
    '"privacy_minimization": privacy_minimization',
    '"raw_private_content_included"',
    '"identifier_scope": "necessary_bounded"',
    '"privacy_shield_review_required": True',
    '"rendered_visual_review": False',
    '"live_evidence_consumption": False',
    '"deployment_verified": False',
    '"rollback_verified": False',
    '"production_accepted": False',
):
    require(needle in reference, f"Security Center 2.0 reference missing fail-closed invariant: {needle}")

require("FR-009" in roadmap and "Security Center 2.0" in roadmap, "roadmap must include FR-009 Security Center 2.0")
require("Source Validated — Development candidate" in roadmap, "FR-009 must remain a bounded source-validation milestone")

print("Wardveil Security Center 2.0 contract validation passed")
