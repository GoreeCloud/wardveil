"""Wardveil adapters for GoreeCloud Mesh evidence coordination.

The evidence adapter emits minimized producer-authoritative metadata only. The
refresh-intent validator accepts bounded Mesh coordination requests only; it
never invokes a Wardveil executor, transfers security authority, or treats a
refresh request as new security evidence.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from urllib.parse import quote
import copy
import json
import re

MESH_EVIDENCE_VERSION = "goreecloud.evidence-envelope.v1"
MESH_REFRESH_INTENT_VERSION = "goreecloud.evidence-refresh-intent.v1"
MESH_REFRESH_CONTRACT = "contracts/mesh.evidence-refresh-intent.schema.json"
MESH_REPOSITORY = "GoreeCloud/goreecloud-mesh"
WARDVEIL_REPOSITORY = "GoreeCloud/goreecloud-wardveil-security"
WARDVEIL_STATUS_CONTRACT = "contracts/wardveil.status.schema.json"
WARDVEIL_RUNTIME_CONTRACT = "contracts/wardveil.runtime.schema.json"
_ALLOWED_CONTRACT_PREFIX = "contracts/wardveil."
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_REFRESH_REASONS = {"stale", "empty", "manual"}
_REFRESH_FIELDS = {
    "version", "id", "coordinator", "producer", "authority_domain", "subject",
    "assertion", "reason", "requested_at", "latest_observed_at",
    "contains_user_content", "contains_secret_material", "authority_transferred",
    "execution_authorized",
}
_STATUS_FIELDS = {
    "contract_version", "scope", "authority", "state", "source_state",
    "evidence", "claim", "privacy",
}
_STATUS_SCOPE_FIELDS = {"kind", "id", "display_name"}
_STATUS_AUTHORITY_FIELDS = {"system", "control", "authoritative"}
_STATUS_EVIDENCE_FIELDS = {"status", "observed_at", "valid_until", "summary", "reference"}
_STATUS_CLAIM_FIELDS = {"protected_by_wardveil"}
_STATUS_PRIVACY_FIELDS = {"details_withheld", "redactions"}
_STATUS_SCOPE_KINDS = {
    "account", "application", "service", "device", "network", "data", "control",
    "platform", "other",
}
_STATUS_STATES = {"protected", "attention", "degraded", "unknown", "not_applicable"}
_STATUS_EVIDENCE_STATES = {"current", "stale", "unavailable", "unverified"}
_RUNTIME_RECORD_TYPES = {
    "trust_decision", "policy_decision", "detection_finding", "scan_finding",
    "protection_action", "quarantine_record", "incident_record", "audit_event",
}
_RUNTIME_SCOPE_FIELDS = {"resource_type", "resource_id", "operation", "principal_class"}
_RUNTIME_PRINCIPAL_CLASSES = {"user", "device", "application", "service", "machine", "system"}
_RUNTIME_ASSERTION_OUTCOME_FIELDS = {
    "trust-evaluation": "trust_state",
    "policy-decision": "policy_decision",
    "protection-result": "execution_status",
    "detection-finding": "detection_disposition",
    "scan-finding": "scan_result",
    "quarantine-state": "review_state",
    "incident-state": "incident_status",
    "security-audit-state": "outcome",
}
_RUNTIME_ASSERTION_RECORD_TYPES = {
    "trust-evaluation": "trust_decision",
    "policy-decision": "policy_decision",
    "protection-result": "protection_action",
    "detection-finding": "detection_finding",
    "scan-finding": "scan_finding",
    "quarantine-state": "quarantine_record",
    "incident-state": "incident_record",
    "security-audit-state": "audit_event",
}
_PERMITTED_ASSERTIONS = {
    "security-status", "runtime-acceptance", "trust-evaluation", "policy-decision",
    "protection-result", "detection-finding", "scan-finding", "quarantine-state",
    "incident-state", "response-state", "security-audit-state",
}


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _parse_timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} is required")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be RFC3339/ISO8601") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include timezone")
    try:
        return parsed.astimezone(timezone.utc)
    except OverflowError as error:
        raise ValueError(f"{field} is outside the supported UTC range") from error


def _evaluation_time(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if value.tzinfo is None:
        raise ValueError("observed_at override must include timezone")
    try:
        return value.astimezone(timezone.utc)
    except OverflowError as error:
        raise ValueError("observed_at override is outside the supported UTC range") from error


def _require_string(value: object, field: str, *, maximum: int | None = None) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")
    result = value.strip()
    if maximum is not None and len(result) > maximum:
        raise ValueError(f"{field} exceeds the approved length")
    return result


def _closed_object(
    value: object,
    field: str,
    *,
    allowed: set[str],
    required: set[str],
) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    unknown = set(value) - allowed
    if unknown:
        raise ValueError(f"unexpected {field} fields: {', '.join(sorted(unknown))}")
    missing = required - set(value)
    if missing:
        raise ValueError(f"missing {field} fields: {', '.join(sorted(missing))}")
    return value


def _validate_status_record(record: dict, *, evaluated_at: datetime) -> dict:
    """Validate the closed Wardveil status contract before security-status emission."""
    unknown = set(record) - _STATUS_FIELDS
    missing = {"contract_version", "scope", "authority", "state", "evidence", "claim", "privacy"} - set(record)
    if unknown:
        raise ValueError(f"unexpected Wardveil status fields: {', '.join(sorted(unknown))}")
    if missing:
        raise ValueError(f"missing Wardveil status fields: {', '.join(sorted(missing))}")
    if record.get("contract_version") != "0.1.0":
        raise ValueError("unsupported Wardveil status contract version")

    scope = _closed_object(
        record.get("scope"),
        "Wardveil status scope",
        allowed=_STATUS_SCOPE_FIELDS,
        required={"kind", "id"},
    )
    kind = _require_string(scope.get("kind"), "Wardveil status scope kind", maximum=128)
    if kind not in _STATUS_SCOPE_KINDS:
        raise ValueError("unsupported Wardveil status scope kind")
    subject_id = _require_string(scope.get("id"), "Wardveil status scope id", maximum=128)
    if "display_name" in scope:
        _require_string(scope.get("display_name"), "Wardveil status display name", maximum=128)

    authority = _closed_object(
        record.get("authority"),
        "Wardveil status authority",
        allowed=_STATUS_AUTHORITY_FIELDS,
        required=_STATUS_AUTHORITY_FIELDS,
    )
    if _require_string(authority.get("system"), "Wardveil status authority system", maximum=128) != "Wardveil Security":
        raise ValueError("security-status evidence must be produced by Wardveil Security authority")
    _require_string(authority.get("control"), "Wardveil status authority control", maximum=128)
    if authority.get("authoritative") is not True:
        raise ValueError("security-status evidence must be producer-authoritative")

    state = _require_string(record.get("state"), "Wardveil status state")
    if state not in _STATUS_STATES:
        raise ValueError("unsupported Wardveil status state")
    if "source_state" in record:
        _require_string(record.get("source_state"), "Wardveil status source_state", maximum=128)

    evidence = _closed_object(
        record.get("evidence"),
        "Wardveil status evidence",
        allowed=_STATUS_EVIDENCE_FIELDS,
        required={"status", "observed_at"},
    )
    evidence_status = _require_string(evidence.get("status"), "Wardveil evidence status")
    if evidence_status not in _STATUS_EVIDENCE_STATES:
        raise ValueError("unsupported Wardveil evidence status")
    producer_observed_at = _parse_timestamp(evidence.get("observed_at"), "Wardveil evidence observed_at")
    if producer_observed_at > evaluated_at:
        raise ValueError("Wardveil status evidence cannot be observed in the future")
    if "summary" in evidence:
        summary = evidence.get("summary")
        if not isinstance(summary, str) or len(summary) > 240:
            raise ValueError("Wardveil status evidence summary is invalid")
    if "reference" in evidence:
        reference = evidence.get("reference")
        if not isinstance(reference, str) or len(reference) > 256:
            raise ValueError("Wardveil status evidence reference is invalid")

    claim = _closed_object(
        record.get("claim"),
        "Wardveil status claim",
        allowed=_STATUS_CLAIM_FIELDS,
        required=_STATUS_CLAIM_FIELDS,
    )
    protected_claim = claim.get("protected_by_wardveil")
    if not isinstance(protected_claim, bool):
        raise ValueError("Wardveil protected claim must be boolean")
    if state == "protected":
        if evidence_status != "current" or protected_claim is not True:
            raise ValueError("protected Wardveil status requires current evidence and protected claim")
    elif protected_claim is not False:
        raise ValueError("non-protected Wardveil status cannot carry a protected claim")

    privacy = _closed_object(
        record.get("privacy"),
        "Wardveil status privacy",
        allowed=_STATUS_PRIVACY_FIELDS,
        required=_STATUS_PRIVACY_FIELDS,
    )
    if not isinstance(privacy.get("details_withheld"), bool):
        raise ValueError("Wardveil status privacy details_withheld must be boolean")
    redactions = privacy.get("redactions")
    if not isinstance(redactions, list) or len(redactions) > 16:
        raise ValueError("Wardveil status privacy redactions are invalid")
    for redaction in redactions:
        _require_string(redaction, "Wardveil status privacy redaction", maximum=128)

    # A Mesh Evidence Envelope always has an expiry. Wardveil emits a status envelope
    # only from currently valid producer evidence; Mesh may subsequently retain and
    # report that envelope as stale after this producer-declared validity window passes.
    if evidence_status != "current":
        raise ValueError("only current Wardveil status evidence can be emitted to Mesh")
    valid_until = _parse_timestamp(evidence.get("valid_until"), "Wardveil evidence valid_until")
    if valid_until <= producer_observed_at:
        raise ValueError("Wardveil status evidence validity must follow observation")
    if valid_until <= evaluated_at:
        raise ValueError("cannot emit expired Wardveil status evidence")

    return {
        "kind": kind,
        "id": subject_id,
        "state": state,
        "observed_at": producer_observed_at,
        "valid_until": valid_until,
        "summary": str(evidence.get("summary") or "").strip(),
        "reference": str(evidence.get("reference") or "").strip(),
    }


def _validate_runtime_record(record: dict, *, evaluated_at: datetime) -> dict:
    """Validate the runtime-record fields relied upon by generic Wardveil assertions."""
    if record.get("contract_version") != "0.1.0":
        raise ValueError("unsupported Wardveil runtime contract version")
    record_type = _require_string(record.get("record_type"), "Wardveil runtime record_type")
    if record_type not in _RUNTIME_RECORD_TYPES:
        raise ValueError("unsupported Wardveil runtime record_type")
    record_id = _require_string(record.get("record_id"), "Wardveil runtime record_id", maximum=128)

    producer = _closed_object(
        record.get("producer"),
        "Wardveil runtime producer",
        allowed={"id", "authoritative"},
        required={"id", "authoritative"},
    )
    producer_id = _require_string(producer.get("id"), "Wardveil runtime producer id", maximum=128)
    if producer.get("authoritative") is not True:
        raise ValueError("record must be producer-authoritative")

    scope = _closed_object(
        record.get("scope"),
        "Wardveil runtime scope",
        allowed=_RUNTIME_SCOPE_FIELDS,
        required={"resource_type", "resource_id"},
    )
    subject_kind = _require_string(scope.get("resource_type"), "Wardveil runtime resource_type", maximum=128)
    subject_id = _require_string(scope.get("resource_id"), "Wardveil runtime resource_id", maximum=128)
    if "operation" in scope:
        _require_string(scope.get("operation"), "Wardveil runtime operation", maximum=128)
    if "principal_class" in scope and scope.get("principal_class") not in _RUNTIME_PRINCIPAL_CLASSES:
        raise ValueError("unsupported Wardveil runtime principal_class")

    record_observed_at = _parse_timestamp(record.get("observed_at"), "Wardveil runtime observed_at")
    if record_observed_at > evaluated_at:
        raise ValueError("Wardveil runtime record cannot be observed in the future")
    evidence_refs = record.get("evidence_refs")
    if not isinstance(evidence_refs, list):
        raise ValueError("Wardveil runtime evidence_refs must be an array")
    for reference in evidence_refs:
        _require_string(reference, "Wardveil runtime evidence reference", maximum=256)

    valid_until = _parse_timestamp(record.get("valid_until"), "Wardveil runtime valid_until")
    if valid_until <= record_observed_at:
        raise ValueError("Wardveil runtime validity must follow observation")
    if valid_until <= evaluated_at:
        raise ValueError("cannot emit expired Wardveil evidence")

    required_by_type = {
        "trust_decision": ("trust_state", {"trusted", "normal", "elevated_risk", "restricted", "blocked"}),
        "policy_decision": ("policy_decision", {"allow", "allow_and_log", "warn", "step_up", "restrict", "quarantine", "revoke", "block", "isolate", "escalate"}),
        "detection_finding": ("detection_disposition", {"informational", "suspicious", "likely_malicious", "confirmed_malicious", "unknown"}),
        "scan_finding": ("scan_result", {"clean", "suspicious", "malicious", "unknown", "unsupported"}),
        "protection_action": ("execution_status", {"requested", "authorized", "executing", "succeeded", "failed", "rejected", "expired"}),
        "quarantine_record": ("review_state", {"pending", "under_review", "released", "removed", "retained"}),
        "incident_record": ("incident_status", {"open", "contained", "remediating", "recovering", "verified", "closed"}),
        "audit_event": ("outcome", {"success", "failure", "denied", "blocked", "partial", "unknown"}),
    }
    field, allowed = required_by_type[record_type]
    if record.get(field) not in allowed:
        raise ValueError(f"Wardveil runtime {record_type} requires a valid {field}")
    if record_type == "detection_finding":
        if record.get("severity") not in {"informational", "low", "medium", "high", "critical"}:
            raise ValueError("Wardveil detection finding requires valid severity")
        confidence = record.get("confidence")
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
            raise ValueError("Wardveil detection finding requires confidence from 0 through 1")
    if record_type == "protection_action":
        if record.get("policy_decision") not in {"allow", "allow_and_log", "warn", "step_up", "restrict", "quarantine", "revoke", "block", "isolate", "escalate"}:
            raise ValueError("Wardveil protection action requires valid policy_decision")
        _require_string(record.get("executor"), "Wardveil protection executor", maximum=128)
        _require_string(record.get("idempotency_key"), "Wardveil protection idempotency_key", maximum=256)
    if record_type == "incident_record" and record.get("severity") not in {"informational", "low", "medium", "high", "critical"}:
        raise ValueError("Wardveil incident record requires valid severity")
    if record_type == "audit_event":
        _require_string(record.get("event_type"), "Wardveil audit event_type", maximum=128)

    return {
        "record_type": record_type,
        "record_id": record_id,
        "producer_id": producer_id,
        "kind": subject_kind,
        "id": subject_id,
        "scope": str(scope.get("operation") or "").strip(),
        "observed_at": record_observed_at,
        "valid_until": valid_until,
    }


def validate_mesh_evidence_refresh_intent(intent: dict, *, now: datetime | None = None) -> dict:
    """Validate a Mesh refresh intent targeted to Wardveil security evidence.

    Validation only establishes that the coordination request is structurally
    bounded and addressed to Wardveil's security authority. It does not refresh
    evidence, invoke Protect/Scan/Response, or authorize any security action.
    """
    if not isinstance(intent, dict):
        raise ValueError("refresh intent must be an object")
    unknown = set(intent) - _REFRESH_FIELDS
    if unknown:
        raise ValueError(f"unexpected refresh intent fields: {', '.join(sorted(unknown))}")
    if intent.get("version") != MESH_REFRESH_INTENT_VERSION:
        raise ValueError("unsupported refresh intent version")

    coordinator = intent.get("coordinator")
    if not isinstance(coordinator, dict) or set(coordinator) != {"system", "repository", "revision", "contract"}:
        raise ValueError("canonical Mesh coordinator identity is required")
    if coordinator.get("system") != "goreecloud-mesh" or coordinator.get("repository") != MESH_REPOSITORY:
        raise ValueError("refresh intent must be coordinated by GoreeCloud Mesh")
    if not _REVISION.fullmatch(str(coordinator.get("revision") or "")):
        raise ValueError("Mesh coordinator revision must be exact")
    if coordinator.get("contract") != MESH_REFRESH_CONTRACT:
        raise ValueError("refresh intent must use the canonical Mesh contract")

    if intent.get("producer") != "wardveil-security" or intent.get("authority_domain") != "security":
        raise ValueError("refresh intent is not targeted to Wardveil security authority")
    subject = intent.get("subject")
    if not isinstance(subject, dict) or set(subject) - {"kind", "id", "scope"}:
        raise ValueError("refresh intent subject is invalid")
    if not str(subject.get("kind") or "").strip() or not str(subject.get("id") or "").strip():
        raise ValueError("refresh intent subject kind and id are required")
    if not str(intent.get("id") or "").strip() or not str(intent.get("assertion") or "").strip():
        raise ValueError("refresh intent id and assertion are required")

    reason = intent.get("reason")
    if reason not in _REFRESH_REASONS:
        raise ValueError("invalid refresh reason")
    evaluated_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    requested_at = _parse_timestamp(intent.get("requested_at"), "requested_at")
    if requested_at > evaluated_at:
        raise ValueError("requested_at cannot be in the future")
    latest_value = intent.get("latest_observed_at")
    latest = _parse_timestamp(latest_value, "latest_observed_at") if latest_value is not None else None
    if latest is not None and latest > requested_at:
        raise ValueError("latest_observed_at cannot be after requested_at")
    if reason == "stale" and latest is None:
        raise ValueError("stale refresh requires latest_observed_at")
    if reason == "empty" and latest is not None:
        raise ValueError("empty refresh cannot claim an existing observation")

    if intent.get("contains_user_content") is not False or intent.get("contains_secret_material") is not False:
        raise ValueError("refresh intent must not contain user content or secret material")
    if intent.get("authority_transferred") is not False or intent.get("execution_authorized") is not False:
        raise ValueError("refresh intent cannot transfer Wardveil authority or authorize execution")
    return copy.deepcopy(intent)


def create_mesh_evidence_envelope(
    record: dict,
    *,
    revision: str,
    assertion: str,
    outcome: str | None = None,
    contract: str | None = None,
    observed_at: datetime | None = None,
) -> dict:
    """Create a minimized Mesh Evidence Envelope from a contract-valid Wardveil record.

    ``security-status`` is intentionally special: its outcome is derived from the
    canonical Wardveil status record and cannot be upgraded by a caller. Other
    assertion families use the Wardveil runtime record contract unless a different
    Wardveil contract is explicitly supplied.
    """
    if not isinstance(record, dict):
        raise ValueError("record must be an object")
    if not _REVISION.fullmatch(revision or ""):
        raise ValueError("revision must be an exact 40-character lowercase Git revision")
    assertion_value = _require_string(assertion, "assertion", maximum=128)
    if assertion_value not in _PERMITTED_ASSERTIONS:
        raise ValueError("assertion is not permitted by the Wardveil Mesh evidence profile")

    evaluated_at = _evaluation_time(observed_at)
    if assertion_value == "security-status":
        contract_value = contract or WARDVEIL_STATUS_CONTRACT
        if contract_value != WARDVEIL_STATUS_CONTRACT:
            raise ValueError("security-status must use the canonical Wardveil status contract")
        status = _validate_status_record(record, evaluated_at=evaluated_at)
        derived_outcome = status["state"]
        if outcome is not None and str(outcome).strip() != derived_outcome:
            raise ValueError("security-status outcome must match the producer status state")

        digest = sha256(_canonical(record)).hexdigest()
        source = status["reference"] or f"wardveil://status/{status['kind']}/{status['id']}"
        summary = status["summary"] or "Wardveil security-status evidence."
        return {
            "version": MESH_EVIDENCE_VERSION,
            "id": f"wardveil-status-{digest[:24]}",
            "producer": {
                "system": "wardveil-security",
                "repository": WARDVEIL_REPOSITORY,
                "revision": revision,
                "contract": contract_value,
            },
            "authority_domain": "security",
            "subject": {
                "kind": status["kind"],
                "id": status["id"],
                "scope": "",
            },
            "assertion": assertion_value,
            "outcome": derived_outcome,
            "source": source,
            "observed_at": status["observed_at"].isoformat().replace("+00:00", "Z"),
            "valid_until": status["valid_until"].isoformat().replace("+00:00", "Z"),
            "data_class": "derived",
            "summary": summary,
            "payload_digest": "sha256:" + digest,
            "contains_user_content": False,
            "contains_secret_material": False,
        }

    contract_value = contract or WARDVEIL_RUNTIME_CONTRACT
    if not isinstance(contract_value, str) or not contract_value.startswith(_ALLOWED_CONTRACT_PREFIX):
        raise ValueError("contract must be a Wardveil contract")
    if contract_value == WARDVEIL_STATUS_CONTRACT:
        raise ValueError("non-status assertions cannot claim the Wardveil status contract")
    if contract_value != WARDVEIL_RUNTIME_CONTRACT:
        raise ValueError("generic Wardveil runtime evidence must use the canonical runtime contract")
    outcome_value = _require_string(outcome, "outcome", maximum=128)
    runtime = _validate_runtime_record(record, evaluated_at=evaluated_at)

    expected_record_type = _RUNTIME_ASSERTION_RECORD_TYPES.get(assertion_value)
    if expected_record_type is None:
        raise ValueError(f"{assertion_value} does not have an approved Wardveil runtime producer binding")
    if runtime["record_type"] != expected_record_type:
        raise ValueError(
            f"{assertion_value} requires Wardveil runtime record_type {expected_record_type}"
        )

    derived_field = _RUNTIME_ASSERTION_OUTCOME_FIELDS[assertion_value]
    producer_outcome = str(record.get(derived_field) or "").strip()
    if outcome_value != producer_outcome:
        raise ValueError(f"{assertion_value} outcome must match Wardveil {derived_field}")

    reason = str(record.get("reason_code") or record.get("decision_reason") or "").strip()
    if len(reason) > 256:
        reason = reason[:256]
    summary = f"Wardveil {assertion_value}: {reason}" if reason else f"Wardveil {assertion_value} evidence."

    return {
        "version": MESH_EVIDENCE_VERSION,
        "id": f"wardveil-{runtime['record_id']}",
        "producer": {
            "system": "wardveil-security",
            "repository": WARDVEIL_REPOSITORY,
            "revision": revision,
            "contract": contract_value,
        },
        "authority_domain": "security",
        "subject": {
            "kind": runtime["kind"],
            "id": runtime["id"],
            "scope": runtime["scope"],
        },
        "assertion": assertion_value,
        "outcome": outcome_value,
        "source": (
            f"wardveil://producers/{quote(runtime['producer_id'], safe='')}"
            f"/records/{quote(runtime['record_id'], safe='')}"
        ),
        "observed_at": runtime["observed_at"].isoformat().replace("+00:00", "Z"),
        "valid_until": runtime["valid_until"].isoformat().replace("+00:00", "Z"),
        "data_class": "derived",
        "summary": summary,
        "payload_digest": "sha256:" + sha256(_canonical(record)).hexdigest(),
        "contains_user_content": False,
        "contains_secret_material": False,
    }