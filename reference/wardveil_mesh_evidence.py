"""Wardveil adapter for GoreeCloud Mesh Evidence Envelope v1.

The adapter emits minimized producer-authoritative metadata only. It does not
transport scan payloads, message/file bodies, credentials, or raw user content.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import re

MESH_EVIDENCE_VERSION = "goreecloud.evidence-envelope.v1"
WARDVEIL_REPOSITORY = "GoreeCloud/goreecloud-wardveil-security"
_ALLOWED_CONTRACT_PREFIX = "contracts/wardveil."
_REVISION = re.compile(r"^[0-9a-f]{40}$")


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("valid_until is required")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("valid_until must be RFC3339/ISO8601") from exc
    if parsed.tzinfo is None:
        raise ValueError("valid_until must include timezone")
    return parsed.astimezone(timezone.utc)


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
