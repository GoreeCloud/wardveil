# Wardveil Runtime Execution Authorization

## Purpose

Wardveil Foundation 0.9 adds a canonical authorization boundary between an authoritative Wardveil Policy decision and a concrete cross-service protection executor.

A policy decision is not, by itself, permission for an arbitrary service to mutate another system. High-impact actions such as restrict, quarantine, revoke, block, isolate, and escalate require an execution authorization bound to the exact policy record, target scope, action, executor, validity window, replay identity, and idempotency identity.

The source reference is `reference/wardveil_runtime_authorization.py`. The machine-readable contract is `contracts/wardveil.runtime-authorization.json`.

## Runtime flow

`authoritative evidence -> Wardveil Trust/Policy -> policy decision -> execution authorization -> authenticated executor -> Wardveil Protect result -> Wardveil Audit`

The authorization step does not transfer ownership of the target resource. The target application, service, infrastructure component, or adapter still executes only the operations for which it has explicit authority.

## Required bindings

Every authorization binds:

- authorization identity;
- authoritative policy issuer;
- exact policy-record identity and SHA-256 digest;
- correlation identity;
- exact executor identity;
- exact policy action;
- exact target scope;
- idempotency key;
- replay nonce;
- issue time and expiry.

Changing the policy record, action, target, executor, correlation identity, or signed authorization material invalidates the authorization.

## Expiry and freshness

Authorizations are intentionally short-lived. The 0.9 contract caps authorization lifetime at five minutes and an authorization may never outlive the policy decision that created it.

Expired, malformed, future-dated beyond the allowed clock-skew window, or policy-detached authorization fails closed.

## Replay and retry semantics

Replay identity and idempotency are separate controls.

- Reuse of the same nonce for different authorization material is rejected.
- A retry of the exact same authorization, nonce, and idempotency key is recognized as an idempotent retry.
- The Protect executor's idempotency ledger prevents the same authorized mutation from being executed twice in the reference flow.

The in-memory reference ledgers are not a production durability claim. A deployed executor requires a durable/shared replay and idempotency store with the consistency properties required by that executor scope.

## Cryptographic boundary

The dependency-free source reference uses HMAC-SHA256 so the authorization contract can be tested without introducing a cryptography or key-management dependency. The algorithm is explicitly labeled `HMAC-SHA256-reference-only`.

This does not prescribe production cryptography or key storage. Production acceptance requires approved key management, key rotation and revocation, authenticated transport, executor identity authentication, and runtime failure/replay testing. Signing secrets must never be embedded in authorization envelopes, shared security records, application source, or public configuration.

## Protect integration

`AuthorizedProtectEngine` is the canonical 0.9 reference cross-service execution path. It verifies the authorization before handing the original policy record and exact idempotency key to the existing `ProtectEngine`.

High-impact actions still require a concrete authorized handler. A valid execution authorization cannot compensate for an executor that lacks action or resource authority, and it cannot make a missing high-impact execution handler valid.

## Audit and evidence

A successful authorization check is only one part of execution evidence. Production systems must persist the resulting protection action and associated audit receipt through Wardveil Audit or an approved authoritative adapter.

The authorization envelope is data-minimized and does not require raw resource content, credentials, session tokens, cookies, or signing secrets.

## GoreeCloud Mesh

GoreeCloud Mesh remains the coordination and governance plane. Runtime authorization may be transported over Mesh or another approved authenticated service channel, but transport does not change Wardveil Policy or target-executor authority. Delivery authenticity and execution authority are distinct checks.

## Production acceptance

The 0.9 source contract remains `unaccepted` for production runtime use until evidence exists for:

- approved production key management;
- authenticated authorization transport;
- durable shared replay and idempotency state;
- authenticated executor identity;
- enforced clock and expiry behavior;
- at least one authorized high-impact executor integration;
- durable audit-receipt persistence;
- key rotation and revocation procedures;
- runtime replay, expiry, tamper, transport-failure, and executor-failure tests.

Foundation 0.9 therefore upgrades Wardveil's source-level execution architecture without claiming that these controls are already deployed.
