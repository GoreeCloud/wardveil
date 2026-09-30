#!/usr/bin/env python3
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_detection_engine_v1 import BehavioralSignal, assess_behavioral_signals
from reference.wardveil_incident_center_v1 import build_incident_review_case

schema = json.loads((ROOT / "contracts/wardveil.incident-center.v1.schema.json").read_text())
doc = (ROOT / "docs/INCIDENT-CENTER-V1.md").read_text()
workflow = (ROOT / ".github/workflows/validate.yml").read_text()
implemented = (ROOT / "docs/IMPLEMENTED-FEATURES.md").read_text()
planned = (ROOT / "docs/PLANNED-FEATURES.md").read_text()
changelog = (ROOT / "docs/CHANGELOGS.md").read_text()

assert schema["additionalProperties"] is False
properties = schema["properties"]
assert properties["record_type"]["const"] == "incident_review_case"
assert properties["incident_established"]["const"] is False
assert properties["execution_authority"]["const"] is False
assert properties["containment_authority"]["const"] is False
assert properties["production_accepted"]["const"] is False
assert set(properties["status"]["enum"]) == {"unknown", "review_required"}

now = datetime(2026, 9, 28, 22, 0, tzinfo=timezone.utc)
def signal(signal_id, category, producer):
    return BehavioralSignal(
        signal_id=signal_id,
        category=category,
        resource_type="application",
        resource_id="validator-app",
        producer_id=producer,
        authority_domain="runtime-security",
        severity="high",
        confidence=0.91,
        observed_at=now - timedelta(minutes=1),
        valid_until=now + timedelta(minutes=4),
        evidence_refs=(f"evidence:{signal_id}",),
        authoritative=True,
    )

assessment = assess_behavioral_signals(
    (signal("validator-1", "credential_harvesting", "identity-monitor"), signal("validator-2", "anomalous_network_activity", "network-monitor")),
    now=now,
)
case = build_incident_review_case((assessment,), now=now)
record = case.as_record()
assert case.status == "review_required"
assert case.incident_established is False
assert case.execution_authority is False
assert case.containment_authority is False
assert record["production_accepted"] is False
assert record["case_id"].startswith("wicv1-")
assert "does not call `create_incident`" in doc
assert "incident_established=false" in doc
assert "Test Wardveil Incident Center V1" in workflow
assert "Validate Wardveil Incident Center V1" in workflow
assert "reference/wardveil_incident_center_v1.py" in workflow
assert "Incident Center V1" in implemented
assert "Incident Center V1" in planned
assert "Incident Center V1" in changelog

print("Wardveil Incident Center V1 Development validation: PASS")
print("Boundary: Detection Engine candidate -> review_required only; no incident, execution, containment, production, or Protected/Covered authority.")
