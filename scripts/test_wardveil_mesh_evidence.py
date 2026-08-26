#!/usr/bin/env python3
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_mesh_evidence import create_mesh_evidence_envelope


def fail(message: str) -> None:
    raise SystemExit(f"Wardveil Mesh evidence test failed: {message}")


now = datetime(2026, 8, 26, 23, 30, tzinfo=timezone.utc)
record = {
    "record_type": "policy_decision",
    "record_id": "decision-001",
    "correlation_id": "corr-001",
    "producer": {"id": "wardveil-policy", "authoritative": True},
    "scope": {"resource_type": "service", "resource_id": "goreecloud-mail", "component": "attachment-ingress"},
    "reason_code": "attachment_policy_satisfied",
    "valid_until": (now + timedelta(hours=1)).isoformat(),
    "raw_payload": "this field is hashed locally but never transported",
}

envelope = create_mesh_evidence_envelope(
    record,
    revision="a" * 40,
    assertion="policy-decision",
    outcome="allow",
    observed_at=now,
)

if envelope["version"] != "goreecloud.evidence-envelope.v1":
    fail("wrong envelope version")
if envelope["producer"]["system"] != "wardveil-security":
    fail("wrong producer")
if envelope["authority_domain"] != "security":
    fail("wrong authority domain")
if envelope["subject"]["id"] != "goreecloud-mail":
    fail("wrong subject")
if envelope["contains_user_content"] or envelope["contains_secret_material"]:
    fail("minimization flags must remain false")
if "raw_payload" in envelope or "record" in envelope:
    fail("raw Wardveil record content must not be transported")
if not envelope["payload_digest"].startswith("sha256:"):
    fail("payload digest is required")

try:
    create_mesh_evidence_envelope(
        record,
        revision="a" * 40,
        assertion="policy-decision",
        outcome="allow",
        contract="contracts/privacy-shield.status.schema.json",
        observed_at=now,
    )
except ValueError:
    pass
else:
    fail("cross-producer contract must be rejected")

expired = dict(record)
expired["valid_until"] = (now - timedelta(seconds=1)).isoformat()
try:
    create_mesh_evidence_envelope(
        expired,
        revision="a" * 40,
        assertion="policy-decision",
        outcome="allow",
        observed_at=now,
    )
except ValueError:
    pass
else:
    fail("expired evidence must be rejected")

print("Wardveil Mesh Evidence Envelope adapter: OK")
