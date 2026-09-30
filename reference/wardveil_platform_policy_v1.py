#!/usr/bin/env python3
"""Bounded GoreeCloud Policy v1 adapter for Wardveil Security.

This module constructs Policy evaluation requests and validates returned Policy
decision evidence. It does not call a Policy runtime, execute obligations,
create Wardveil execution authorization, or establish protection/production
acceptance.
"""
from __future__ import annotations

from datetime import datetime
import math
import unicodedata
from typing import Any

POLICY_CONTRACT_REPOSITORY = "GoreeCloud/policy"
POLICY_CONTRACT_REVISION = "46071886da37a6566b69cc923005eef64cce2bcc"
POLICY_EVALUATION_REQUEST_CONTRACT_ID = "https://goreecloud.com/contracts/policy/evaluation-request/v1"
POLICY_DECISION_CONTRACT_ID = "https://goreecloud.com/contracts/policy/decision/v1"

POLICY_DECISIONS = ("allow", "deny", "conditional", "defer", "indeterminate", "error")
REQUEST_FIELDS = ("policy_id", "policy_version", "authority", "subject", "resource", "action")
DECISION_FIELDS = {
    "decision", "policy_id", "policy_version", "authority", "subject", "resource",
    "action", "reason", "matched_rule_ids", "obligations", "evaluated_at", "fresh",
}
SENSITIVE_TOKENS = (
    "api_key", "apikey", "authorization", "cookie", "credential", "password",
    "passwd", "private_key", "secret", "token", "access_token", "refresh_token",
    "content", "payload", "message", "query", "body", "email", "phone", "address",
    "ip_address", "user_id", "session_id",
)
MAX_TEXT = 1000
MAX_ITEMS = 128
MAX_DEPTH = 8


def _text(value: Any, field: str, maximum: int = MAX_TEXT) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field}_must_be_string")
    if value != value.strip() or not value or len(value) > maximum:
        raise ValueError(f"{field}_must_be_bounded_canonical_text")
    if any(unicodedata.category(char).startswith("C") for char in value):
        raise ValueError(f"{field}_contains_control_character")
    return value


def _normalized_key(value: str) -> str:
    return value.lower().replace("-", "_").replace(" ", "_")


def _sensitive_key(value: str) -> bool:
    normalized = _normalized_key(value)
    return any(token in normalized for token in SENSITIVE_TOKENS)


def _sanitize_json(value: Any, path: str, depth: int = 0) -> Any:
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
        return [_sanitize_json(item, f"{path}[{index}]", depth + 1) for index, item in enumerate(value)]
    if isinstance(value, dict):
        if len(value) > MAX_ITEMS:
            raise ValueError(f"{path}_too_many_fields")
        result: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            key = _text(raw_key, f"{path}_key", 128)
            if _sensitive_key(key):
                raise ValueError(f"{path}.{key}_not_allowed")
            result[key] = _sanitize_json(raw_value, f"{path}.{key}", depth + 1)
        return result
    raise ValueError(f"{path}_not_json_safe")


def _string_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_ITEMS:
        raise ValueError(f"{field}_must_be_bounded_string_list")
    result = [_text(item, f"{field}_item") for item in value]
    if len(result) != len(set(result)):
        raise ValueError(f"{field}_must_be_unique")
    return result


def _timestamp(value: Any, field: str) -> str:
    text = _text(value, field, 64)
    if not (text.endswith("Z") or (len(text) >= 6 and text[-6] in "+-" and text[-3] == ":")):
        raise ValueError(f"{field}_must_include_timezone")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field}_invalid") from error
    if parsed.tzinfo is None:
        raise ValueError(f"{field}_must_include_timezone")
    return text


def build_policy_evaluation_request(
    *,
    policy_id: str,
    policy_version: str,
    authority: str,
    subject: str,
    resource: str,
    action: str,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    request: dict[str, Any] = {
        "policy_id": _text(policy_id, "policy_id"),
        "policy_version": _text(policy_version, "policy_version"),
        "authority": _text(authority, "authority"),
        "subject": _text(subject, "subject"),
        "resource": _text(resource, "resource"),
        "action": _text(action, "action"),
    }
    if context is not None:
        if not isinstance(context, dict):
            raise ValueError("context_must_be_object")
        request["context"] = _sanitize_json(context, "context")
    return request


def validate_policy_decision_evidence(
    decision: Any,
    *,
    expected_request: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(decision, dict) or set(decision) != DECISION_FIELDS:
        raise ValueError("policy_decision_shape_invalid")

    outcome = _text(decision["decision"], "decision", 32)
    if outcome not in POLICY_DECISIONS:
        raise ValueError("policy_decision_unsupported")

    validated = {
        "decision": outcome,
        "policy_id": _text(decision["policy_id"], "policy_id"),
        "policy_version": _text(decision["policy_version"], "policy_version"),
        "authority": _text(decision["authority"], "authority"),
        "subject": _text(decision["subject"], "subject"),
        "resource": _text(decision["resource"], "resource"),
        "action": _text(decision["action"], "action"),
        "reason": _text(decision["reason"], "reason"),
        "matched_rule_ids": _string_list(decision["matched_rule_ids"], "matched_rule_ids"),
        "obligations": _string_list(decision["obligations"], "obligations"),
        "evaluated_at": _timestamp(decision["evaluated_at"], "evaluated_at"),
    }
    if not isinstance(decision["fresh"], bool):
        raise ValueError("policy_decision_fresh_must_be_boolean")
    validated["fresh"] = decision["fresh"]

    if expected_request is not None:
        if not isinstance(expected_request, dict):
            raise ValueError("expected_request_must_be_object")
        for field in REQUEST_FIELDS:
            expected = _text(expected_request.get(field), f"expected_request_{field}")
            if validated[field] != expected:
                raise ValueError(f"policy_decision_provenance_mismatch_{field}")

    return {
        **validated,
        "decision_evidence_usable": bool(validated["fresh"]),
        "execution_authority": False,
        "protection_authority": False,
        "obligations_executed": False,
        "production_accepted": False,
    }
