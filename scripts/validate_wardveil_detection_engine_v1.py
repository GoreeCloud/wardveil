#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "contracts" / "wardveil.detection-engine.v1.schema.json"
DOC = ROOT / "docs/DETECTION-ENGINE-V1.md"
REFERENCE = ROOT / "reference" / "wardveil_detection_engine_v1.py"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
doc = DOC.read_text(encoding="utf-8")
reference = REFERENCE.read_text(encoding="utf-8")

require(schema.get("title") == "Wardveil Behavioral Detection Engine V1 Assessment", "unexpected detection schema title")
require(schema.get("additionalProperties") is False, "detection schema must reject top-level extension fields")

required = set(schema.get("required", []))
for field in (
    "contract_version",
    "record_type",
    "resource",
    "disposition",
    "severity",
    "confidence",
    "correlated",
    "signal_categories",
    "producer_ids",
    "evidence_refs",
    "reason_codes",
    "observed_at",
    "valid_until",
    "incident_candidate",
    "execution_authority",
):
    require(field in required, f"detection schema missing required field: {field}")

props = schema["properties"]
require(props["contract_version"].get("const") == "0.1.0", "detection contract version drifted")
require(props["record_type"].get("const") == "detection_assessment", "unexpected detection record type")
require(props["execution_authority"].get("const") is False, "detection assessment must never grant execution authority")
require("unknown" in props["disposition"].get("enum", []), "detection disposition must retain unknown")
require(props["confidence"].get("minimum") == 0 and props["confidence"].get("maximum") == 1, "confidence bounds drifted")

for phrase in (
    "Development source foundation",
    "fresh, authoritative",
    "If no fresh authoritative evidence remains",
    "incident_candidate=true",
    "execution_authority=false",
    "independent production acceptance",
):
    require(phrase in doc, f"detection documentation missing invariant: {phrase}")

for phrase in (
    'CONTRACT_VERSION = "0.1.0"',
    '"no_fresh_authoritative_behavioral_evidence"',
    '"conflicting_signal_id_reuse"',
    '"mixed_resource_signals_require_partitioning"',
    'execution_authority: bool = False',
    '"execution_authority": False',
):
    require(phrase in reference, f"detection reference missing invariant: {phrase}")

print("Wardveil Detection Engine V1 contract validation passed.")
