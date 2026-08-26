"""Authenticated runtime delivery for Wardveil Mesh evidence envelopes.

Credential issuance is owned by GoreeCloud Identity. This client consumes a
short-lived bearer credential that is expected to identify service
``wardveil-security`` with ``mesh.evidence.write`` scope. The credential is
never copied into evidence, logs, return values, or persistence.
"""
from __future__ import annotations

import json
from urllib import error, parse, request


def _validate_destination(mesh_base_url: str) -> str:
    value = str(mesh_base_url or "").strip().rstrip("/")
    parsed = parse.urlparse(value)
    if parsed.scheme == "https":
        return value
    if parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}:
        return value
    raise ValueError("Mesh evidence delivery requires HTTPS except for loopback development")


def deliver_mesh_evidence(
    envelope: dict,
    *,
    mesh_base_url: str,
    bearer_token: str,
    timeout_seconds: float = 5.0,
) -> dict:
    """Deliver one already-minimized Wardveil envelope to GoreeCloud Mesh."""
    if not isinstance(envelope, dict):
        raise ValueError("envelope must be an object")
    producer = envelope.get("producer") or {}
    if producer.get("system") != "wardveil-security":
        raise ValueError("Wardveil delivery only accepts wardveil-security envelopes")
    token = str(bearer_token or "").strip()
    if not token:
        raise ValueError("GoreeCloud Identity bearer credential is required")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")

    endpoint = _validate_destination(mesh_base_url) + "/v1/evidence/envelopes"
    body = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    req = request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "goreecloud-wardveil-security/mesh-evidence",
        },
    )
    try:
        with request.urlopen(req, timeout=timeout_seconds) as response:
            status = response.status
            payload = json.loads(response.read().decode("utf-8"))
    except error.HTTPError as exc:
        try:
            detail = json.loads(exc.read().decode("utf-8")).get("error", "Mesh rejected evidence delivery")
        except Exception:
            detail = "Mesh rejected evidence delivery"
        raise RuntimeError(f"Mesh evidence delivery failed with HTTP {exc.code}: {detail}") from exc
    except error.URLError as exc:
        raise RuntimeError("Mesh evidence delivery failed before acceptance") from exc

    if status not in {200, 201}:
        raise RuntimeError(f"Mesh evidence delivery returned unexpected HTTP {status}")
    delivered = payload.get("envelope") or {}
    if delivered.get("id") != envelope.get("id"):
        raise RuntimeError("Mesh delivery receipt did not bind to the submitted evidence id")
    if payload.get("producer_service_id") != "wardveil-security":
        raise RuntimeError("Mesh delivery receipt did not bind to Wardveil service identity")
    return {
        "evidence_id": delivered.get("id"),
        "replayed": payload.get("replayed") is True,
        "accepted_at": payload.get("accepted_at"),
        "producer_service_id": payload.get("producer_service_id"),
    }
