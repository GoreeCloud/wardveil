"""Wardveil runtime-acceptance evidence adapter for GoreeCloud Mesh.

This adapter is intentionally separate from the generic Wardveil runtime-record
adapter. It transports bounded infrastructure acceptance state only. It does
not create or upgrade trust, protection, scan, quarantine, incident, response,
or production-acceptance authority.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
from urllib.parse import quote
import json
import re

MESH_EVIDENCE_VERSION = "goreecloud.evidence-envelope.v1"
WARDVEIL_REPOSITORY = "GoreeCloud/goreecloud-wardveil-security"
WARDVEIL_RUNTIME_ACCEPTANCE_CONTRACT = "contracts/wardveil.cloudflare.acceptance-evidence.schema.json"
WARDVEIL_RUNTIME_ACCEPTANCE_COMPONENT = "Wardveil Cloudflare persistence runtime"
WARDVEIL_RUNTIME_ACCEPTANCE_SUBJECT = "goreecloud-wardveil-persistence"
RUNTIME_ACCEPTANCE_VALIDITY_SECONDS = 3600
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_ACCEPTANCE_STATES = {"unaccepted", "degraded", "accepted"}
_CHECK_STATES = {"pending", "passed", "failed", "expired", "unavailable"}
_REQUIRED_CHECKS = (
    "deployed_revision_match",
    "health_endpoint",
    "authorized_append_read",
    "duplicate_record_rejection",
    "checkpoint_non_regression",
    "retention_alarm_evidence",
    "payload_digest_verification",
    "pitr_availability",
    "restore_verification_exercise",
    "observability_failure_evidence",
    "public_mutation_surface_absent",
)
_TOP_LEVEL_FIELDS = {
    "schema_version",
    "component",
    "environment",
    "deployed_revision",
    "collected_at",
    "valid_until",
    "acceptance_status",
    "checks",
    "storage_health_is_protection_claim",
    "everkeep_recovery_authority_preserved",
}
_CHECK_FIELDS = {"status", "observed_at", "source", "summary"}


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


def _evaluation_time(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if value.tzinfo is None:
        raise ValueError("evaluation time must include timezone")
    return value.astimezone(timezone.utc)


def _require_string(value: object, field: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")
    result = value.strip()
    if len(result) > maximum:
        raise ValueError(f"{field} exceeds the approved length")
    return result


def validate_runtime_acceptance_manifest(manifest: dict, *, now: datetime | None = None) -> dict:
    """Validate current producer-declared runtime acceptance evidence.

    The one-hour validity window is a Wardveil producer policy. Consumers may
    evaluate it but cannot extend, replace, or synthesize it.
    """
    if not isinstance(manifest, dict):
        raise ValueError("runtime acceptance manifest must be an object")
    if set(manifest) != _TOP_LEVEL_FIELDS:
        missing = _TOP_LEVEL_FIELDS - set(manifest)
        extra = set(manifest) - _TOP_LEVEL_FIELDS
        detail = []
        if missing:
            detail.append("missing=" + ",".join(sorted(missing)))
        if extra:
            detail.append("extra=" + ",".join(sorted(extra)))
        raise ValueError("runtime acceptance manifest fields are not closed: " + " ".join(detail))
    if manifest.get("schema_version") != 1:
        raise ValueError("unsupported runtime acceptance manifest schema version")
    if manifest.get("component") != WARDVEIL_RUNTIME_ACCEPTANCE_COMPONENT:
        raise ValueError("runtime acceptance component is not authoritative Wardveil persistence")

    environment = _require_string(manifest.get("environment"), "environment", maximum=64)
    deployed_revision = _require_string(manifest.get("deployed_revision"), "deployed_revision", maximum=40)
    if _REVISION.fullmatch(deployed_revision) is None or deployed_revision == "0" * 40:
        raise ValueError("runtime acceptance requires an exact non-placeholder deployed revision")

    evaluated_at = _evaluation_time(now)
    collected_at = _parse_timestamp(manifest.get("collected_at"), "collected_at")
    valid_until = _parse_timestamp(manifest.get("valid_until"), "valid_until")
    if collected_at > evaluated_at:
        raise ValueError("runtime acceptance evidence cannot be collected in the future")
    if valid_until - collected_at != timedelta(seconds=RUNTIME_ACCEPTANCE_VALIDITY_SECONDS):
        raise ValueError("runtime acceptance valid_until must use the canonical one-hour producer window")
    if valid_until <= evaluated_at:
        raise ValueError("cannot emit expired runtime acceptance evidence")

    acceptance_status = manifest.get("acceptance_status")
    if acceptance_status not in _ACCEPTANCE_STATES:
        raise ValueError("unsupported runtime acceptance status")
    if manifest.get("storage_health_is_protection_claim") is not False:
        raise ValueError("storage health cannot become a Wardveil protection claim")
    if manifest.get("everkeep_recovery_authority_preserved") is not True:
        raise ValueError("Everkeep recovery authority must remain preserved")

    checks = manifest.get("checks")
    if not isinstance(checks, dict) or tuple(checks) != _REQUIRED_CHECKS:
        raise ValueError("runtime acceptance checks must exactly match the canonical ordered set")
    for name in _REQUIRED_CHECKS:
        check = checks[name]
        if not isinstance(check, dict) or set(check) != _CHECK_FIELDS:
            raise ValueError(f"runtime acceptance check {name} is not a closed check object")
        status = check.get("status")
        if status not in _CHECK_STATES:
            raise ValueError(f"runtime acceptance check {name} has unsupported status")
        summary = _require_string(check.get("summary"), f"{name}.summary", maximum=2000)
        del summary
        observed_value = check.get("observed_at")
        source_value = check.get("source")
        if observed_value is not None:
            observed_at = _parse_timestamp(observed_value, f"{name}.observed_at")
            if observed_at > collected_at:
                raise ValueError(f"runtime acceptance check {name} is observed after collection")
        if source_value is not None:
            _require_string(source_value, f"{name}.source", maximum=512)
        if status == "passed" and (observed_value is None or source_value is None):
            raise ValueError(f"passed runtime acceptance check {name} requires observation and source")

    if acceptance_status == "accepted" and any(checks[name]["status"] != "passed" for name in _REQUIRED_CHECKS):
        raise ValueError("accepted runtime state requires every canonical check to pass")

    return {
        "environment": environment,
        "deployed_revision": deployed_revision,
        "acceptance_status": acceptance_status,
        "collected_at": collected_at,
        "valid_until": valid_until,
    }


def create_runtime_acceptance_mesh_evidence(
    manifest: dict,
    *,
    revision: str,
    now: datetime | None = None,
) -> dict:
    """Create minimized Mesh evidence from a current Wardveil acceptance manifest."""
    if _REVISION.fullmatch(revision or "") is None:
        raise ValueError("revision must be an exact 40-character lowercase Git revision")
    validated = validate_runtime_acceptance_manifest(manifest, now=now)
    digest = sha256(_canonical(manifest)).hexdigest()
    environment = validated["environment"]
    deployed_revision = validated["deployed_revision"]
    status = validated["acceptance_status"]
    return {
        "version": MESH_EVIDENCE_VERSION,
        "id": f"wardveil-runtime-acceptance-{digest[:24]}",
        "producer": {
            "system": "wardveil-security",
            "repository": WARDVEIL_REPOSITORY,
            "revision": revision,
            "contract": WARDVEIL_RUNTIME_ACCEPTANCE_CONTRACT,
        },
        "authority_domain": "security",
        "subject": {
            "kind": "runtime",
            "id": WARDVEIL_RUNTIME_ACCEPTANCE_SUBJECT,
            "scope": environment,
        },
        "assertion": "runtime-acceptance",
        "outcome": status,
        "source": (
            "wardveil://runtime-acceptance/"
            + quote(environment, safe="")
            + "/"
            + deployed_revision
        ),
        "observed_at": validated["collected_at"].isoformat().replace("+00:00", "Z"),
        "valid_until": validated["valid_until"].isoformat().replace("+00:00", "Z"),
        "data_class": "derived",
        "summary": f"Wardveil persistence runtime acceptance: {status}.",
        "payload_digest": "sha256:" + digest,
        "contains_user_content": False,
        "contains_secret_material": False,
    }
