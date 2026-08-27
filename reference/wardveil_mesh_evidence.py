"""Wardveil adapters for GoreeCloud Mesh evidence coordination.

The evidence adapter emits minimized producer-authoritative metadata only. The
refresh-intent validator accepts bounded Mesh coordination requests only; it
never invokes a Wardveil executor, transfers security authority, or treats a
refresh request as new security evidence.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import copy
import json
import re

MESH_EVIDENCE_VERSION = "goreecloud.evidence-envelope.v1"
MESH_REFRESH_INTENT_VERSION = "goreecloud.evidence-refresh-intent.v1"
MESH_REFRESH_CONTRACT = "contracts/mesh.evidence-refresh-intent.schema.json"
MESH_REPOSITORY = "GoreeCloud/goreecloud-mesh"
WARDVEIL_REPOSITORY = "GoreeCloud/goreecloud-wardveil-security"
_ALLOWED_CONTRACT_PREFIX = "contracts/wardveil."
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_REFRESH_REASONS = {"stale", "empty", "manual"}
_REFRESH_FIELDS = {
    "version", "id", "coordinator", "producer", "authority_domain", "subject",
    "assertion", "reason", "requested_at", "latest_observed_at",
    "contains_user_content", "contains_secret_material", "authority_transferred",
    "execution_authorized",
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
    return parsed.astimezone(timezone.utc)


def _parse_time(value: object) -> datetime:
    return _parse_timestamp(value, "valid_until")


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
    outcome: str,
    contract: str = "contracts/wardveil.status.schema.json",
    observed_at: datetime | None = None,
) -> dict:
    """Create a minimized Mesh Evidence Envelope from a Wardveil record."""
    if not isinstance(record, dict):
        raise ValueError("record must be an object")
    if not _REVISION.fullmatch(revision or ""):
        raise ValueError("revision must be an exact 40-character lowercase Git revision")
    if not isinstance(contract, str) or not contract.startswith(_ALLOWED_CONTRACT_PREFIX):
        raise ValueError("contract must be a Wardveil contract")
    if not assertion or not outcome:
        raise ValueError("assertion and outcome are required")

    producer = record.get("producer") or {}
    if producer.get("authoritative") is not True:
        raise ValueError("record must be producer-authoritative")

    record_id = str(record.get("record_id") or "").strip()
    scope = record.get("scope") or {}
    subject_kind = str(scope.get("resource_type") or "").strip()
    subject_id = str(scope.get("resource_id") or "").strip()
    if not record_id or not subject_kind or not subject_id:
        raise ValueError("record identity and resource scope are required")

    now = (observed_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    valid_until = _parse_time(record.get("valid_until"))
    if valid_until <= now:
        raise ValueError("cannot emit expired Wardveil evidence")

    reason = str(record.get("reason_code") or record.get("decision_reason") or "").strip()
    if len(reason) > 256:
        reason = reason[:256]
    summary = f"Wardveil {assertion}: {reason}" if reason else f"Wardveil {assertion} evidence."

    return {
        "version": MESH_EVIDENCE_VERSION,
        "id": f"wardveil-{record_id}",
        "producer": {
            "system": "wardveil-security",
            "repository": WARDVEIL_REPOSITORY,
            "revision": revision,
            "contract": contract,
        },
        "authority_domain": "security",
        "subject": {
            "kind": subject_kind,
            "id": subject_id,
            "scope": str(scope.get("scope") or scope.get("component") or "").strip(),
        },
        "assertion": assertion,
        "outcome": outcome,
        "source": f"wardveil://records/{record_id}",
        "observed_at": now.isoformat().replace("+00:00", "Z"),
        "valid_until": valid_until.isoformat().replace("+00:00", "Z"),
        "data_class": "derived",
        "summary": summary,
        "payload_digest": "sha256:" + sha256(_canonical(record)).hexdigest(),
        "contains_user_content": False,
        "contains_secret_material": False,
    }
