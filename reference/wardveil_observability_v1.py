#!/usr/bin/env python3
"""Privacy-minimized GoreeCloud Observability v1 signal construction for Wardveil.

This module constructs contract-shaped operational evidence only. It does not
publish telemetry, authenticate a producer, retain telemetry, alert, or establish
monitoring/production acceptance.
"""
from __future__ import annotations

from datetime import datetime
import math
import unicodedata
from typing import Any

OBSERVABILITY_CONTRACT_REPOSITORY = "GoreeCloud/observability"
OBSERVABILITY_CONTRACT_REVISION = "a7f6a65f442d3e517baddbe7b6ce7c250d142c8c"
OBSERVABILITY_OPERATIONAL_SIGNAL_CONTRACT_ID = "https://goreecloud.com/contracts/observability/operational-signal/v1"
OBSERVABILITY_STATES = (
    "healthy", "degraded", "failed", "unavailable", "unknown", "stale",
    "partially_observed", "not_monitored", "not_applicable",
)
SENSITIVE_TOKENS = (
    "api_key", "apikey", "authorization", "cookie", "credential", "password",
    "passwd", "private_key", "secret", "token", "access_token", "refresh_token",
    "content", "payload", "message", "query", "body", "email", "phone", "address",
    "ip_address", "user_id", "session_id", "device_id", "account_id",
)
MAX_ITEMS = 128
MAX_TEXT = 1000
MAX_DEPTH = 8


def _text(value: Any, field: str, maximum: int = MAX_TEXT) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > maximum:
        raise ValueError(f"{field}_must_be_bounded_canonical_text")
    if any(unicodedata.category(char).startswith("C") for char in value):
        raise ValueError(f"{field}_contains_control_character")
    return value


def _timestamp(value: Any, field: str) -> tuple[str, datetime]:
    text = _text(value, field, 64)
    if not (text.endswith("Z") or (len(text) >= 6 and text[-6] in "+-" and text[-3] == ":")):
        raise ValueError(f"{field}_must_include_timezone")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field}_invalid") from error
    if parsed.tzinfo is None:
        raise ValueError(f"{field}_must_include_timezone")
    return text, parsed


def _sensitive(key: str) -> bool:
    normalized = key.lower().replace("-", "_").replace(" ", "_")
    return any(token in normalized for token in SENSITIVE_TOKENS)


def _sanitize(value: Any, path: str, depth: int = 0) -> Any:
    if depth > MAX_DEPTH:
        raise ValueError(f"{path}_too_deep")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        return _text(value, path)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if not math.isfinite(float(value)):
            raise ValueError(f"{path}_number_invalid")
        return value
    if isinstance(value, list):
        if len(value) > MAX_ITEMS:
            raise ValueError(f"{path}_too_many_items")
        return [_sanitize(item, f"{path}[{index}]", depth + 1) for index, item in enumerate(value)]
    if isinstance(value, dict):
        if len(value) > MAX_ITEMS:
            raise ValueError(f"{path}_too_many_fields")
        result: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            key = _text(raw_key, f"{path}_key", 128)
            if _sensitive(key):
                raise ValueError(f"{path}.{key}_not_allowed")
            result[key] = _sanitize(raw_value, f"{path}.{key}", depth + 1)
        return result
    raise ValueError(f"{path}_not_json_safe")


def build_operational_signal(
    *,
    signal_id: str,
    source: str,
    signal_type: str,
    state: str,
    observed_at: str,
    collected_at: str,
    ttl_seconds: int,
    component_id: str = "goreecloud-wardveil-security",
    correlation_id: str | None = None,
    attributes: dict[str, Any] | None = None,
    collection_gaps: list[str] | None = None,
) -> dict[str, Any]:
    state = _text(state, "state", 64)
    if state not in OBSERVABILITY_STATES:
        raise ValueError("observability_state_unsupported")
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or not 1 <= ttl_seconds <= 86400:
        raise ValueError("ttl_seconds_out_of_range")

    observed_text, observed = _timestamp(observed_at, "observed_at")
    collected_text, collected = _timestamp(collected_at, "collected_at")
    if collected < observed:
        raise ValueError("collected_at_before_observed_at")

    if correlation_id is not None:
        correlation_id = _text(correlation_id, "correlation_id", 256)

    attributes = {} if attributes is None else attributes
    if not isinstance(attributes, dict):
        raise ValueError("attributes_must_be_object")

    collection_gaps = [] if collection_gaps is None else collection_gaps
    if not isinstance(collection_gaps, list) or len(collection_gaps) > MAX_ITEMS:
        raise ValueError("collection_gaps_must_be_bounded_list")
    gaps = [_text(item, "collection_gap", 256) for item in collection_gaps]
    if len(gaps) != len(set(gaps)):
        raise ValueError("collection_gaps_must_be_unique")
    if state == "healthy" and gaps:
        raise ValueError("healthy_signal_cannot_claim_collection_gaps")

    return {
        "signal_id": _text(signal_id, "signal_id", 256),
        "component_id": _text(component_id, "component_id", 256),
        "source": _text(source, "source", 256),
        "signal_type": _text(signal_type, "signal_type", 256),
        "state": state,
        "observed_at": observed_text,
        "collected_at": collected_text,
        "ttl_seconds": ttl_seconds,
        "correlation_id": correlation_id,
        "attributes": _sanitize(attributes, "attributes"),
        "collection_gaps": gaps,
    }
