"""Reference GoreeCloud Identity and key-lifecycle acceptance model for Wardveil.

Wardveil does not mint GoreeCloud Identity credentials and this module does not
perform cryptographic verification. It consumes bounded verification evidence
from an approved GoreeCloud Identity verifier and evaluates whether the
identity/key lifecycle evidence is sufficient for the requested Wardveil use.

Presentation, caller assertions, successful transport, or possession of a token
must never be promoted into Identity authority by this reference model.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Mapping

SCHEMA_VERSION = "0.1.0"
IDENTITY_AUTHORITY = "goreecloud-identity"
PINNED_IDENTITY_REVISION = "4ce7d193ff251ce3e7c39b8a19712317dd013c5d"
MESH_PROFILE = "goreecloud-identity.mesh-service-token.v1"
MESH_AUDIENCE = "goreecloud-mesh"
MESH_ALGORITHM = "RS256"
MESH_MAX_LIFETIME_SECONDS = 900
MESH_CLOCK_SKEW_SECONDS = 60
MIN_RSA_BITS = 2048
_KID_RE = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
_SERVICE_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")

PRODUCTION_GATES = (
    "identity_production_accepted",
    "live_issuance_deployed",
    "jwks_deployed",
    "durable_private_key_custody_accepted",
    "rotation_verified",
    "credential_revocation_verified",
    "replay_protection_verified",
    "expiration_enforcement_verified",
    "key_usage_audit_verified",
    "emergency_revocation_verified",
    "runtime_validated",
)


def _parse_time(value: Any, name: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty timestamp")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _bool(record: Mapping[str, Any], name: str) -> bool:
    value = record.get(name)
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be boolean")
    return value


def _string(record: Mapping[str, Any], name: str, limit: int = 256) -> str:
    value = record.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    value = value.strip()
    if len(value) > limit:
        raise ValueError(f"{name} exceeds {limit} characters")
    return value


def evaluate_identity_key_lifecycle(
    record: Mapping[str, Any], *, evaluated_at: str | None = None
) -> dict[str, Any]:
    """Evaluate Identity/key lifecycle evidence without becoming Identity authority.

    For the currently published Identity Mesh credential profile, exact profile
    semantics are checked. A Mesh credential is never accepted as direct
    Wardveil execution authorization because its audience is GoreeCloud Mesh.
    Future direct Wardveil credential profiles must arrive through an approved,
    source-validated GoreeCloud Identity contract and cannot be inferred here.
    """
    authority = _string(record, "identity_authority", 128)
    profile = _string(record, "credential_profile", 160)
    identity_revision = _string(record, "identity_revision", 64)
    usage = _string(record, "usage", 64)
    service_id = _string(record, "service_id", 64)
    intended_audience = _string(record, "intended_audience", 128)

    if not _SERVICE_ID_RE.fullmatch(service_id):
        raise ValueError("service_id must be a canonical lowercase GoreeCloud service identifier")
    if usage not in {"mesh_transport", "direct_wardveil_execution"}:
        raise ValueError("unsupported Identity credential usage")

    required_scopes = record.get("required_scopes")
    if not isinstance(required_scopes, list) or not required_scopes:
        raise ValueError("required_scopes must be a non-empty list")
    if not all(isinstance(scope, str) and scope.strip() for scope in required_scopes):
        raise ValueError("required_scopes must contain non-empty strings")
    required_scopes = sorted(set(scope.strip() for scope in required_scopes))

    credential = record.get("credential_verification")
    lifecycle = record.get("key_lifecycle")
    acceptance = record.get("acceptance_evidence")
    if not isinstance(credential, Mapping):
        raise ValueError("credential_verification must be an object")
    if not isinstance(lifecycle, Mapping):
        raise ValueError("key_lifecycle must be an object")
    if not isinstance(acceptance, Mapping):
        raise ValueError("acceptance_evidence must be an object")

    evaluated = _parse_time(evaluated_at, "evaluated_at") if evaluated_at else datetime.now(timezone.utc)
    issued_at = _parse_time(credential.get("issued_at"), "issued_at")
    expires_at = _parse_time(credential.get("expires_at"), "expires_at")
    if expires_at <= issued_at:
        raise ValueError("credential expiry must be later than issuance")

    algorithm = _string(credential, "algorithm", 32)
    issuer = _string(credential, "issuer", 128)
    audience = _string(credential, "audience", 128)
    kid = _string(credential, "kid", 128)
    credential_service_id = _string(credential, "service_id", 64)
    if credential_service_id != service_id:
        raise ValueError("credential service identity does not match represented service")

    reasons: list[str] = []
    profile_source_validated = _bool(acceptance, "profile_source_validated")
    identity_revision_pinned = identity_revision == PINNED_IDENTITY_REVISION
    if authority != IDENTITY_AUTHORITY:
        reasons.append("identity_authority_mismatch")
    if not identity_revision_pinned:
        reasons.append("identity_revision_not_pinned")
    if not profile_source_validated:
        reasons.append("identity_profile_not_source_validated")

    if profile == MESH_PROFILE:
        if algorithm != MESH_ALGORITHM:
            reasons.append("identity_algorithm_mismatch")
        if issuer != IDENTITY_AUTHORITY:
            reasons.append("identity_issuer_mismatch")
        if audience != MESH_AUDIENCE or intended_audience != MESH_AUDIENCE:
            reasons.append("identity_audience_mismatch")
        if usage != "mesh_transport":
            reasons.append("mesh_credential_not_direct_wardveil_authority")
        lifetime = (expires_at - issued_at).total_seconds()
        if lifetime > MESH_MAX_LIFETIME_SECONDS:
            reasons.append("credential_lifetime_exceeds_identity_profile")
        if not _KID_RE.fullmatch(kid):
            reasons.append("identity_kid_invalid")
    elif usage == "direct_wardveil_execution":
        # A future direct profile must be explicitly approved by GoreeCloud
        # Identity. This reference model cannot infer or self-authorize it.
        reasons.append("direct_wardveil_identity_profile_not_approved")
    else:
        reasons.append("identity_profile_not_supported")

    now_with_skew = evaluated.timestamp() + MESH_CLOCK_SKEW_SECONDS
    if issued_at.timestamp() > now_with_skew:
        reasons.append("credential_issued_in_future")
    if evaluated.timestamp() >= expires_at.timestamp() + MESH_CLOCK_SKEW_SECONDS:
        reasons.append("credential_expired")

    verification_checks = (
        "signature_verified",
        "protected_header_verified",
        "issuer_verified",
        "audience_verified",
        "time_verified",
        "workload_identity_verified",
        "scope_verified",
        "kid_resolved",
        "key_not_revoked",
        "trusted_jwks_transport_verified",
    )
    for check in verification_checks:
        if not _bool(credential, check):
            reasons.append(check.replace("_verified", "") + "_unverified")

    rsa_bits = lifecycle.get("rsa_key_bits")
    rsa_exponent = lifecycle.get("rsa_public_exponent")
    if not isinstance(rsa_bits, int) or isinstance(rsa_bits, bool) or rsa_bits < MIN_RSA_BITS:
        reasons.append("identity_key_strength_unacceptable")
    if not isinstance(rsa_exponent, int) or isinstance(rsa_exponent, bool) or rsa_exponent < 3 or rsa_exponent % 2 == 0:
        reasons.append("identity_rsa_public_exponent_unacceptable")
    if _string(lifecycle, "jwks_media_type", 64).lower() != "application/json":
        reasons.append("identity_jwks_media_type_unacceptable")

    credential_accepted = not reasons

    production_gate_state = {gate: _bool(acceptance, gate) for gate in PRODUCTION_GATES}
    missing_production_gates = [gate for gate, satisfied in production_gate_state.items() if not satisfied]
    requested_production = _bool(acceptance, "request_production_acceptance")
    production_accepted = credential_accepted and requested_production and not missing_production_gates

    if requested_production and missing_production_gates:
        reasons.extend(f"production_gate_pending:{gate}" for gate in missing_production_gates)
    if not requested_production:
        reasons.append("production_acceptance_not_requested")

    return {
        "schema_version": SCHEMA_VERSION,
        "evaluated_at": evaluated.isoformat().replace("+00:00", "Z"),
        "identity_authority": authority,
        "identity_revision": identity_revision,
        "credential_profile": profile,
        "usage": usage,
        "service_id": service_id,
        "intended_audience": intended_audience,
        "required_scopes": required_scopes,
        "credential_verification": {
            "algorithm": algorithm,
            "issuer": issuer,
            "audience": audience,
            "kid": kid,
            "issued_at": issued_at.isoformat().replace("+00:00", "Z"),
            "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
            "accepted": credential_accepted,
        },
        "key_lifecycle": {
            "rsa_key_bits": rsa_bits,
            "rsa_public_exponent": rsa_exponent,
            "jwks_media_type": _string(lifecycle, "jwks_media_type", 64),
            "production_gates": production_gate_state,
        },
        "acceptance": {
            "profile_source_validated": profile_source_validated,
            "identity_revision_pinned": identity_revision_pinned,
            "credential_accepted": credential_accepted,
            "runtime_validated": production_gate_state["runtime_validated"],
            "production_accepted": production_accepted,
            "claim_authority": production_accepted,
        },
        "reason_codes": sorted(set(reasons)),
    }
