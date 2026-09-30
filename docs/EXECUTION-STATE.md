# Wardveil Durable Execution State

## Purpose

Wardveil Foundation 0.9 requires high-impact cross-service execution to survive process restarts and failure without converting retries into duplicate security mutations.

This layer persists two distinct facts:

1. an exact runtime authorization has been claimed for one executor and idempotency identity; and
2. the resulting authoritative Wardveil Protect record has been finalized into a durable execution receipt.

The source reference is `reference/wardveil_execution_state.py`. The machine-readable contract is `contracts/wardveil.execution-state.json`.

## Safe execution flow

`verify authorization -> durable claim -> local executor authorization -> execute -> authoritative Protect record -> durable receipt -> Wardveil Audit/Security Center`

A durable claim is written before the external side effect. If the process later loses certainty about whether the side effect happened, Wardveil does not blindly execute the action again.

## Replay and idempotency

The execution-state claim binds the exact authorization digest, authorization ID, correlation ID, executor ID, action, scope, nonce, idempotency key, issue time, and expiry.

The following fail closed:

- the same nonce presented with different authorization material;
- the same executor idempotency key presented under a different nonce;
- an expired authorization presented as a new claim;
- a protection result whose scope, action, executor, correlation ID, or idempotency identity does not match the claim;
- conflicting finalization for an already finalized claim.

An exact retry after finalization returns the original persisted receipt and must not invoke the handler again.

## Uncertain outcome rule

A claim that exists without a finalized execution receipt is not treated as unused authorization. It becomes `execution_reconciliation_required`.

That state can occur when a process fails after the durable claim and before receipt persistence, including the difficult case where an external side effect may have completed but the process failed before recording the result.

Wardveil deliberately favors safety over availability here: automatic blind re-execution is prohibited. A production executor must provide an application-specific reconciliation mechanism capable of determining the authoritative target state or safely completing an idempotent operation.

The durable Wardveil claim cannot make a non-idempotent external API exactly-once by itself. Production executors remain responsible for idempotency or an equivalent authoritative reconciliation mechanism at the system that owns the side effect.

## Execution receipts

A receipt is created only from an authoritative `protection_action` record with a final outcome of `succeeded`, `rejected`, or `failed`.

The receipt binds:

- the exact execution-authorization digest;
- authorization and correlation identity;
- executor identity;
- action and target scope;
- idempotency identity;
- the full normalized Wardveil Protect record;
- SHA-256 digest of the Protect record;
- completion time;
- SHA-256 digest of the receipt itself.

The receipt is evidence of the represented Protect outcome. It does not broaden the executor's authority and does not prove unrelated controls succeeded.

## Cloudflare persistence path

The existing Wardveil persistence Worker and SQLite-backed Durable Object are extended with service-binding-only execution-state storage. The persistence adapter stores replay/idempotency claims and minimized execution receipts without adding a public mutation endpoint.

The public HTTP boundary remains `/healthz` plus a default 404 response. Execution-state reads and writes are internal RPC operations.

Persistence is not a security-state authority. A successful durable claim is not evidence that an action executed, and a healthy persistence service cannot create or upgrade a `Protected by Wardveil` claim.

## Privacy Shield boundary

Shared execution state must be data-minimized. Signing secrets, private keys, passwords, access tokens, refresh tokens, session tokens, cookies, raw authentication headers, and unrelated raw resource content are prohibited from the execution-state record.

The normalized target scope and Wardveil protection record are retained only to the extent necessary for replay safety, auditability, investigation, and authorized reconciliation. Privacy Shield remains the platform-wide privacy and data-minimization authority.

## Everkeep boundary

Durable execution-state backup and recovery capability does not make Wardveil the recovery authority. Everkeep remains responsible for platform-wide resilience, backup, restore, and recovery verification. Recovery of Wardveil execution-state persistence must preserve claim/receipt integrity and must not silently discard a pending uncertain-outcome state.

## Production acceptance

This source upgrade does not make runtime execution authorization production-accepted. The production status remains `unaccepted` until the deployment has evidence for:

- approved production signing and key management;
- authenticated executor identity and authorization transport;
- deployed durable replay/idempotency storage;
- deployed durable execution-receipt storage;
- at least one authorized high-impact executor;
- executor-side idempotency or authoritative side-effect reconciliation;
- uncertain-outcome operational procedures;
- key rotation and revocation;
- crash, replay, tamper, expiry, persistence-failure, and recovery exercises;
- Wardveil Audit receipt ingestion and Security Center visibility.

Source CI validates the contract and reference behavior. It is not deployment evidence.
