#!/usr/bin/env python3
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_mesh_evidence import (
    create_mesh_evidence_envelope,
    validate_mesh_evidence_refresh_intent,
)
from reference.wardveil_mesh_refresh_response import create_mesh_evidence_refresh_response


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

refresh = {
    "version": "goreecloud.evidence-refresh-intent.v1",
    "id": "refresh-wardveil-mail-001",
    "coordinator": {
        "system": "goreecloud-mesh",
        "repository": "GoreeCloud/goreecloud-mesh",
        "revision": "b" * 40,
        "contract": "contracts/mesh.evidence-refresh-intent.schema.json",
    },
    "producer": "wardveil-security",
    "authority_domain": "security",
    "subject": {"kind": "service", "id": "goreecloud-mail", "scope": "runtime"},
    "assertion": "security-status",
    "reason": "stale",
    "requested_at": now.isoformat(),
    "latest_observed_at": (now - timedelta(hours=2)).isoformat(),
    "contains_user_content": False,
    "contains_secret_material": False,
    "authority_transferred": False,
    "execution_authorized": False,
}
accepted = validate_mesh_evidence_refresh_intent(refresh, now=now)
if accepted["producer"] != "wardveil-security" or accepted["execution_authorized"]:
    fail("refresh intent changed Wardveil authority or execution boundary")
if "outcome" in accepted or "security_status" in accepted:
    fail("refresh intent must not manufacture Wardveil security truth")

wrong_domain = dict(refresh)
wrong_domain["authority_domain"] = "privacy"
try:
    validate_mesh_evidence_refresh_intent(wrong_domain, now=now)
except ValueError:
    pass
else:
    fail("cross-authority refresh intent must be rejected")

execution = dict(refresh)
execution["execution_authorized"] = True
try:
    validate_mesh_evidence_refresh_intent(execution, now=now)
except ValueError:
    pass
else:
    fail("refresh intent must not authorize Wardveil execution")

response = create_mesh_evidence_refresh_response(
    refresh,
    response_id="wardveil-refresh-response-001",
    revision="d" * 40,
    status="completed",
    reason_code="evidence-issued",
    responded_at=now,
    evidence_envelope_id="wardveil-decision-002",
    now=now,
)
if response["version"] != "goreecloud.evidence-refresh-response.v1":
    fail("wrong refresh response version")
if response["intent"]["id"] != refresh["id"] or response["intent"]["coordinator_revision"] != refresh["coordinator"]["revision"]:
    fail("refresh response did not bind the exact Mesh intent")
if response["producer"]["system"] != "wardveil-security" or response["authority_domain"] != "security":
    fail("refresh response changed Wardveil producer authority")
if not response["evidence_produced"] or response.get("evidence_envelope_id") != "wardveil-decision-002":
    fail("completed refresh response did not preserve separate evidence reference")
for forbidden in ("outcome", "verdict", "fresh", "protected"):
    if forbidden in response:
        fail(f"refresh response manufactured Wardveil security truth: {forbidden}")
if response["execution_authorized"] or response["authority_transferred"]:
    fail("refresh response granted security execution or transferred authority")

try:
    create_mesh_evidence_refresh_response(
        refresh,
        response_id="wardveil-refresh-response-002",
        revision="d" * 40,
        status="received",
        evidence_envelope_id="wardveil-decision-003",
        now=now,
    )
except ValueError:
    pass
else:
    fail("non-completed refresh response must not claim produced evidence")

print("Wardveil Mesh Evidence Envelope, refresh-intent, and refresh-response adapters: OK")
