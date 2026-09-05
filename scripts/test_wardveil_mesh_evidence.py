#!/usr/bin/env python3
from datetime import datetime, timedelta, timezone
from pathlib import Path
import copy
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.wardveil_mesh_evidence import (
    create_mesh_evidence_envelope,
    validate_mesh_evidence_refresh_intent,
)
from reference.wardveil_mesh_refresh_response import create_mesh_evidence_refresh_response
from reference.wardveil_mesh_refresh_handoff import create_mesh_evidence_refresh_response_for_evidence


def fail(message: str) -> None:
    raise SystemExit(f"Wardveil Mesh evidence test failed: {message}")


def expect_value_error(callback, message: str) -> None:
    try:
        callback()
    except ValueError:
        return
    fail(message)


now = datetime(2026, 8, 26, 23, 30, tzinfo=timezone.utc)
record = {
    "contract_version": "0.1.0",
    "record_type": "policy_decision",
    "record_id": "decision-001",
    "correlation_id": "corr-001",
    "producer": {"id": "wardveil-policy", "authoritative": True},
    "scope": {
        "resource_type": "service",
        "resource_id": "goreecloud-mail",
        "operation": "attachment-ingress",
    },
    "observed_at": now.isoformat(),
    "valid_until": (now + timedelta(hours=1)).isoformat(),
    "evidence_refs": ["wardveil://evidence/attachment-policy-001"],
    "policy_decision": "allow",
    "reason_code": "attachment_policy_satisfied",
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
if envelope["producer"]["contract"] != "contracts/wardveil.runtime.schema.json":
    fail("runtime assertion must identify the runtime producer contract")
if envelope["authority_domain"] != "security":
    fail("wrong authority domain")
if envelope["subject"] != {
    "kind": "service",
    "id": "goreecloud-mail",
    "scope": "attachment-ingress",
}:
    fail("runtime subject was not derived from producer scope")
if envelope["observed_at"] != now.isoformat().replace("+00:00", "Z"):
    fail("runtime envelope must preserve producer observation time")
if envelope["contains_user_content"] or envelope["contains_secret_material"]:
    fail("minimization flags must remain false")
if "raw_payload" in envelope or "record" in envelope:
    fail("raw Wardveil record content must not be transported")
if not envelope["payload_digest"].startswith("sha256:"):
    fail("payload digest is required")

expect_value_error(
    lambda: create_mesh_evidence_envelope(
        record,
        revision="a" * 40,
        assertion="policy-decision",
        outcome="block",
        observed_at=now,
    ),
    "policy-decision outcome must not diverge from producer decision",
)

expect_value_error(
    lambda: create_mesh_evidence_envelope(
        record,
        revision="a" * 40,
        assertion="policy-decision",
        outcome="allow",
        contract="contracts/wardveil.status.schema.json",
        observed_at=now,
    ),
    "non-status assertion must not claim the Wardveil status contract",
)

expect_value_error(
    lambda: create_mesh_evidence_envelope(
        record,
        revision="a" * 40,
        assertion="policy-decision",
        outcome="allow",
        contract="contracts/privacy-shield.status.schema.json",
        observed_at=now,
    ),
    "cross-producer contract must be rejected",
)

expired = copy.deepcopy(record)
expired["valid_until"] = (now - timedelta(seconds=1)).isoformat()
expect_value_error(
    lambda: create_mesh_evidence_envelope(
        expired,
        revision="a" * 40,
        assertion="policy-decision",
        outcome="allow",
        observed_at=now,
    ),
    "expired runtime evidence must be rejected",
)

status_record = {
    "contract_version": "0.1.0",
    "scope": {"kind": "service", "id": "goreecloud-mail"},
    "authority": {
        "system": "Wardveil Security",
        "control": "wardveil-policy",
        "authoritative": True,
    },
    "state": "protected",
    "source_state": "policy-satisfied",
    "evidence": {
        "status": "current",
        "observed_at": now.isoformat(),
        "valid_until": (now + timedelta(hours=1)).isoformat(),
        "summary": "Wardveil has current authoritative evidence for this service.",
        "reference": "wardveil://status/goreecloud-mail/current",
    },
    "claim": {"protected_by_wardveil": True},
    "privacy": {"details_withheld": True, "redactions": ["raw-policy-detail"]},
}

status_envelope = create_mesh_evidence_envelope(
    status_record,
    revision="d" * 40,
    assertion="security-status",
    observed_at=now,
)
if status_envelope["producer"]["contract"] != "contracts/wardveil.status.schema.json":
    fail("security-status must identify the canonical Wardveil status contract")
if status_envelope["outcome"] != "protected":
    fail("security-status outcome must be derived from producer state")
if status_envelope["subject"] != {"kind": "service", "id": "goreecloud-mail", "scope": ""}:
    fail("security-status subject must come from the closed status scope")
if status_envelope["source"] != status_record["evidence"]["reference"]:
    fail("security-status should preserve the opaque producer evidence reference")
if status_envelope["summary"] != status_record["evidence"]["summary"]:
    fail("security-status should preserve the bounded producer summary")

expect_value_error(
    lambda: create_mesh_evidence_envelope(
        record,
        revision="d" * 40,
        assertion="security-status",
        outcome="protected",
        observed_at=now,
    ),
    "runtime policy record must not be relabeled as canonical security-status evidence",
)

expect_value_error(
    lambda: create_mesh_evidence_envelope(
        status_record,
        revision="d" * 40,
        assertion="security-status",
        outcome="attention",
        observed_at=now,
    ),
    "caller must not override canonical security-status outcome",
)

stale_status = copy.deepcopy(status_record)
stale_status["evidence"]["status"] = "stale"
stale_status["evidence"]["valid_until"] = (now - timedelta(seconds=1)).isoformat()
expect_value_error(
    lambda: create_mesh_evidence_envelope(
        stale_status,
        revision="d" * 40,
        assertion="security-status",
        outcome="protected",
        observed_at=now,
    ),
    "stale protected status must not be emitted as current Mesh evidence",
)

false_attention = copy.deepcopy(status_record)
false_attention["state"] = "attention"
expect_value_error(
    lambda: create_mesh_evidence_envelope(
        false_attention,
        revision="d" * 40,
        assertion="security-status",
        observed_at=now,
    ),
    "non-protected status must not retain a protected claim",
)

attention = copy.deepcopy(status_record)
attention["state"] = "attention"
attention["claim"]["protected_by_wardveil"] = False
attention_envelope = create_mesh_evidence_envelope(
    attention,
    revision="d" * 40,
    assertion="security-status",
    observed_at=now,
)
if attention_envelope["outcome"] != "attention":
    fail("non-protected current status outcome must still derive from producer state")

non_authoritative = copy.deepcopy(attention)
non_authoritative["authority"]["authoritative"] = False
expect_value_error(
    lambda: create_mesh_evidence_envelope(
        non_authoritative,
        revision="d" * 40,
        assertion="security-status",
        observed_at=now,
    ),
    "non-authoritative status must not be emitted as producer-authoritative Mesh evidence",
)

extended_status = copy.deepcopy(attention)
extended_status["privacy"]["raw_detail"] = "must-not-exist"
expect_value_error(
    lambda: create_mesh_evidence_envelope(
        extended_status,
        revision="d" * 40,
        assertion="security-status",
        observed_at=now,
    ),
    "status record must remain closed to unapproved privacy fields",
)

future_status = copy.deepcopy(attention)
future_status["evidence"]["observed_at"] = (now + timedelta(seconds=1)).isoformat()
expect_value_error(
    lambda: create_mesh_evidence_envelope(
        future_status,
        revision="d" * 40,
        assertion="security-status",
        observed_at=now,
    ),
    "future Wardveil status observations must fail closed",
)

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
    "subject": {"kind": "service", "id": "goreecloud-mail", "scope": ""},
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
expect_value_error(
    lambda: validate_mesh_evidence_refresh_intent(wrong_domain, now=now),
    "cross-authority refresh intent must be rejected",
)

execution = dict(refresh)
execution["execution_authorized"] = True
expect_value_error(
    lambda: validate_mesh_evidence_refresh_intent(execution, now=now),
    "refresh intent must not authorize Wardveil execution",
)

response = create_mesh_evidence_refresh_response(
    refresh,
    response_id="wardveil-refresh-response-001",
    revision="d" * 40,
    status="completed",
    reason_code="evidence-issued",
    responded_at=now,
    evidence_envelope_id=status_envelope["id"],
    now=now,
)
if response["version"] != "goreecloud.evidence-refresh-response.v1":
    fail("wrong refresh response version")
if response["intent"]["id"] != refresh["id"] or response["intent"]["coordinator_revision"] != refresh["coordinator"]["revision"]:
    fail("refresh response did not bind the exact Mesh intent")
if response["producer"]["system"] != "wardveil-security" or response["authority_domain"] != "security":
    fail("refresh response changed Wardveil producer authority")
if not response["evidence_produced"] or response.get("evidence_envelope_id") != status_envelope["id"]:
    fail("completed refresh response did not preserve separate evidence reference")
for forbidden in ("outcome", "verdict", "fresh", "protected"):
    if forbidden in response:
        fail(f"refresh response manufactured Wardveil security truth: {forbidden}")
if response["execution_authorized"] or response["authority_transferred"]:
    fail("refresh response granted security execution or transferred authority")

expect_value_error(
    lambda: create_mesh_evidence_refresh_response(
        refresh,
        response_id="wardveil-refresh-response-002",
        revision="d" * 40,
        status="received",
        evidence_envelope_id="wardveil-status-not-produced",
        now=now,
    ),
    "non-completed refresh response must not claim produced evidence",
)

handoff_response = create_mesh_evidence_refresh_response_for_evidence(
    refresh,
    response_id="wardveil-refresh-handoff-001",
    revision="d" * 40,
    evidence_envelope=status_envelope,
    responded_at=now,
    now=now,
)
if handoff_response.get("evidence_envelope_id") != status_envelope["id"] or not handoff_response["evidence_produced"]:
    fail("validated handoff did not bind the actual Wardveil evidence envelope")
if "outcome" in handoff_response or handoff_response["execution_authorized"] or handoff_response["authority_transferred"]:
    fail("validated handoff receipt crossed the Wardveil authority boundary")

old_handoff = copy.deepcopy(status_envelope)
old_handoff["observed_at"] = (now - timedelta(seconds=1)).isoformat()
expect_value_error(
    lambda: create_mesh_evidence_refresh_response_for_evidence(
        refresh,
        response_id="wardveil-refresh-handoff-old",
        revision="d" * 40,
        evidence_envelope=old_handoff,
        responded_at=now,
        now=now,
    ),
    "pre-request Wardveil evidence must not satisfy a refresh handoff",
)

wrong_revision_handoff = copy.deepcopy(status_envelope)
wrong_revision_handoff["producer"]["revision"] = "e" * 40
expect_value_error(
    lambda: create_mesh_evidence_refresh_response_for_evidence(
        refresh,
        response_id="wardveil-refresh-handoff-revision",
        revision="d" * 40,
        evidence_envelope=wrong_revision_handoff,
        responded_at=now,
        now=now,
    ),
    "Wardveil evidence from another producer revision must be rejected",
)

wrong_subject_handoff = copy.deepcopy(status_envelope)
wrong_subject_handoff["subject"]["id"] = "goreecloud-drive"
expect_value_error(
    lambda: create_mesh_evidence_refresh_response_for_evidence(
        refresh,
        response_id="wardveil-refresh-handoff-subject",
        revision="d" * 40,
        evidence_envelope=wrong_subject_handoff,
        responded_at=now,
        now=now,
    ),
    "Wardveil evidence for another subject must be rejected",
)

print("Wardveil Mesh Evidence Envelope producer-contract binding, refresh-intent, refresh-response, and validated handoff adapters: OK")
