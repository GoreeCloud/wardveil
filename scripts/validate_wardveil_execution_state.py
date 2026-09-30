#!/usr/bin/env python3
"""Validate Wardveil Foundation 0.9 durable execution-state invariants."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "wardveil.execution-state.json"
DOC = ROOT / "docs/EXECUTION-STATE.md"
REFERENCE = ROOT / "reference" / "wardveil_execution_state.py"


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def main() -> None:
    for path in (CONTRACT, DOC, REFERENCE):
        require(path.is_file(), f"missing execution-state artifact: {path.relative_to(ROOT)}")

    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    doc = DOC.read_text(encoding="utf-8")
    reference = REFERENCE.read_text(encoding="utf-8")

    require(contract.get("contract") == "goreecloud.wardveil.execution-state", "unexpected execution-state contract id")
    require(contract.get("contract_version") == "0.1.0", "unexpected execution-state contract version")
    require(contract.get("foundation_version") == "0.9.0", "execution-state contract must remain on Foundation 0.9")

    claim = contract.get("claim") or {}
    require(claim.get("nonce_conflict_fails_closed") is True, "nonce conflict must fail closed")
    require(claim.get("executor_idempotency_conflict_fails_closed") is True, "executor idempotency conflict must fail closed")
    require(claim.get("pending_retry_disposition") == "execution_reconciliation_required", "pending retries must require reconciliation")
    require(claim.get("blind_reexecution_after_uncertain_outcome_allowed") is False, "blind uncertain-outcome re-execution must remain prohibited")
    require(claim.get("expired_authorization_claim_allowed") is False, "expired authorization claims must remain prohibited")

    receipt = contract.get("receipt") or {}
    require(set(receipt.get("required_outcomes") or []) == {"succeeded", "rejected", "failed"}, "execution receipt outcome set drifted")
    for key in (
        "authoritative_protection_record_required",
        "exact_correlation_binding_required",
        "exact_action_binding_required",
        "exact_scope_binding_required",
        "exact_executor_binding_required",
        "exact_idempotency_binding_required",
        "protection_record_digest_required",
        "receipt_digest_required",
        "conflicting_finalization_fails_closed",
        "idempotent_finalization_returns_original_receipt",
    ):
        require(receipt.get(key) is True, f"execution receipt invariant missing: {key}")

    privacy = contract.get("privacy") or {}
    for key in ("signing_secrets_allowed", "credentials_allowed", "session_tokens_allowed", "cookies_allowed"):
        require(privacy.get(key) is False, f"execution state must exclude sensitive field class: {key}")
    require(privacy.get("raw_resource_content_required") is False, "raw resource content must not be required")
    require(privacy.get("data_minimization_required") is True, "execution state must require data minimization")

    cloudflare = contract.get("cloudflare_reference") or {}
    require(cloudflare.get("backend") == "Durable Object SQLite", "unexpected execution-state persistence backend")
    require(cloudflare.get("public_mutation_api_allowed") is False, "public execution-state mutation API must remain prohibited")
    require(cloudflare.get("service_binding_rpc_only") is True, "execution-state persistence must remain service-binding RPC-only")

    authority = contract.get("authority") or {}
    for key in (
        "persistence_is_security_state_authority",
        "persistence_grants_executor_authority",
        "successful_claim_proves_action_executed",
        "successful_receipt_persistence_can_replace_local_executor_authorization",
    ):
        require(authority.get(key) is False, f"authority boundary drifted: {key}")

    require(contract.get("production_runtime_status") == "unaccepted", "execution-state production status must remain unaccepted")
    remaining = set(contract.get("remaining_acceptance_requirements") or [])
    for phrase in (
        "deployed durable replay and idempotency storage",
        "deployed durable execution-receipt storage",
        "executor-side idempotency for external side effects",
        "uncertain-outcome reconciliation procedure",
        "runtime crash, replay, tamper, expiry, storage-failure, and recovery tests",
    ):
        require(phrase in remaining, f"missing production acceptance remainder: {phrase}")

    for phrase in (
        "execution_reconciliation_required",
        "automatic blind re-execution is prohibited",
        "The durable Wardveil claim cannot make a non-idempotent external API exactly-once by itself.",
        "Persistence is not a security-state authority.",
        "production status remains `unaccepted`",
        "Source CI validates the contract and reference behavior. It is not deployment evidence.",
    ):
        require(phrase in doc, f"execution-state documentation missing boundary: {phrase}")

    for token in (
        "class InMemoryExecutionStateStore",
        "class DurableAuthorizedProtectCoordinator",
        "execution_reconciliation_required",
        "executor_idempotency_conflict",
        "execution_receipt_conflict",
        "execution_receipt_persistence_failed",
        "protection_record_digest_sha256",
        "receipt_digest_sha256",
    ):
        require(token in reference, f"execution-state reference missing invariant: {token}")

    for forbidden in ("access_token", "refresh_token", "private_key", "session_token", "cookie_value"):
        require(forbidden not in contract, f"execution-state contract contains forbidden secret-bearing field: {forbidden}")

    print("Wardveil durable execution-state validation passed.")


if __name__ == "__main__":
    main()
