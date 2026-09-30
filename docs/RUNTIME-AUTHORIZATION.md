# Wardveil Runtime Execution Authorization

## Purpose

Wardveil Foundation 0.9 adds a canonical authorization boundary between an authoritative Wardveil Policy decision and a concrete cross-service protection executor.

A policy decision is not, by itself, permission for an arbitrary service to mutate another system. High-impact actions such as restrict, quarantine, revoke, block, isolate, and escalate require an execution authorization bound to the exact policy record, target scope, action, executor, signing-key identity, validity window, replay identity, and idempotency identity.

The source reference is `reference/wardveil_runtime_authorization.py`. The machine-readable contract is `contracts/wardveil.runtime-authorization.json`.

Foundation 0.9 also defines the service-identity and signing-key lifecycle in `SERVICE-IDENTITY.md`, `contracts/wardveil.service-identity.json`, and `reference/wardveil_service_identity.py`, plus the durable replay/idempotency and execution-receipt layer in `EXECUTION-STATE.md`, `contracts/wardveil.execution-state.json`, and `reference/wardveil_execution_state.py`.

## Runtime flow

`authoritative evidence -> Wardveil Trust/Policy -> active issuer identity -> active signing key -> key-ID-bound execution authorization -> durable execution claim -> authenticated active executor -> Wardveil Protect result -> durable execution receipt -> Wardveil Audit`

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
- signing-key identity (`signing_key_id`);
- idempotency key;
- replay nonce;
- issue time and expiry.

The signing-key ID is nonsecret metadata and is itself covered by the authorization signature. Changing the policy record, action, target, executor, key ID, correlation identity, or other signed authorization material invalidates the authorization.

## Expiry and freshness

Authorizations are intentionally short-lived. The 0.9 contract caps authorization lifetime at five minutes and an authorization may never outlive the policy decision that created it.

Expired, malformed, future-dated beyond the allowed clock-skew window, policy-detached, unknown-key, revoked-key, or identity-invalid authorization fails closed in the identity-aware path.

A verifier may reject an envelope at an earlier trust boundary before reaching its authorization TTL check. For example, a retired key whose bounded verification overlap has ended is rejected as an expired signing key even if the authorization envelope is also expired. This ordering does not make the envelope usable; it preserves the stronger current trust boundary.

## Replay, retry, and durable claim semantics

Replay identity and idempotency are separate controls.

- Reuse of the same nonce for different authorization material is rejected.
- Reuse of one executor/idempotency-key pair under a different authorization claim is rejected by the durable execution-state model.
- An exact retry after a finalized execution returns the original durable receipt without invoking the handler again.
- A durable claim with no finalized receipt is `execution_reconciliation_required`; it is not treated as unused authorization.
- Automatic blind re-execution after an uncertain outcome is prohibited.

The original in-memory authorization ledger remains a dependency-free conformance mechanism. Foundation 0.9 now also contains a durable-state reference and a deployable Cloudflare Durable Object persistence surface, but source availability is not deployment evidence.

A durable Wardveil claim cannot make an external non-idempotent API exactly-once. A production executor must provide target-system idempotency or an authoritative reconciliation mechanism for external side effects.

## Service identity and key lifecycle

The stronger Foundation 0.9 path requires explicit first-party service identity and capability checks in addition to cryptographic verification.

- an authorization issuer must be active and carry `issue_execution_authorization`;
- a bound executor must be active and carry `execute_protection_action`;
- suspended, revoked, expired, unknown, or capability-mismatched identities fail closed;
- an active signing key may sign;
- a retired key may verify only inside its bounded rotation overlap and may not sign;
- a revoked key fails immediately for signing and verification;
- an unknown key, issuer/key mismatch, or algorithm mismatch fails closed.

Service identity, a signing key, or a valid signature never grants the executor authority over the underlying target resource.

## Cryptographic boundary

The dependency-free source reference uses HMAC-SHA256 so the authorization contract can be tested without introducing a cryptography or key-management dependency. The algorithm is explicitly labeled `HMAC-SHA256-reference-only`.

The reference identity/keyring layer keeps key material separate from service/key metadata and binds each authorization to a nonsecret `signing_key_id`. It demonstrates rotation and revocation semantics but is not a production key-management system.

This does not prescribe production cryptography or key storage. Production acceptance requires an approved signature algorithm and key-management system, service-identity issuance/authentication, key rotation and revocation, authenticated transport, executor identity authentication, and runtime failure/replay testing. Signing secrets must never be embedded in authorization envelopes, durable execution-state records, shared security records, application source, public configuration, or logs.

For the Cloudflare source candidate, `cloudflare/authorization-issuer/` separates signing from the persistence Durable Object. Its signing operation is Worker-RPC/service-binding oriented and public HTTP remains health-only. The signing secret is a required encrypted binding; the repository contains only binding names and nonsecret identity/key IDs. This is deployable source, not evidence that a production secret or signer has been deployed.

## Protect integration

`AuthorizedProtectEngine` remains the low-level Foundation 0.9 reference cross-service execution gate. It verifies the authorization before handing the original policy record and exact idempotency key to the existing `ProtectEngine`.

`create_identity_bound_execution_authorization(...)` and `verify_identity_bound_execution_authorization(...)` add the service-identity and key-lifecycle checks around the base authorization contract.

`DurableAuthorizedProtectCoordinator` demonstrates the stronger production-oriented sequence: cryptographic verification, durable claim, Protect execution, and durable receipt finalization.

High-impact actions still require a concrete authorized handler. A valid execution authorization or durable claim cannot compensate for an executor that lacks action or resource authority, and neither can make a missing high-impact execution handler valid.

## Audit and evidence

A successful authorization check or durable claim is only part of execution evidence. The resulting authoritative `protection_action` record is bound into a minimized execution receipt containing its exact digest, action, scope, executor, correlation identity, idempotency identity, and final outcome.

Production systems must persist that receipt through an approved durable execution-state backend and make the resulting evidence available to Wardveil Audit and appropriate Security Center investigation surfaces. Key and service identity metadata may be retained where required for provenance, but secret key material must never be copied into Audit or Security Center evidence.

The authorization envelope and execution-state record are data-minimized and do not require raw resource content, credentials, session tokens, cookies, raw authorization headers, or signing secrets.

## GoreeCloud Mesh

GoreeCloud Mesh remains the coordination and governance plane. Runtime authorization may be transported over Mesh or another approved authenticated service channel, but transport does not change Wardveil Policy or target-executor authority. Delivery authenticity, service identity, key trust, and execution authority are distinct checks.

Durable replay/idempotency state must be scoped consistently with the executor domain. Mesh delivery itself is not a replay ledger, does not reactivate a suspended/revoked identity or key, and does not authorize re-execution after an uncertain outcome.

## Production acceptance

The 0.9 runtime-authorization, service-identity, and durable execution-state source contracts remain `unaccepted` for production runtime use until evidence exists for:

- approved production signature algorithm and key management;
- production service-identity issuance and authentication;
- least-privilege issuer and executor capability assignment;
- authenticated authorization transport;
- deployed secret/key bindings without source exposure;
- deployed durable shared replay and idempotency state;
- deployed durable execution-receipt storage;
- authenticated executor identity;
- enforced clock and expiry behavior;
- tested key rotation overlap and immediate revocation behavior;
- at least one authorized high-impact executor integration;
- executor-side idempotency or authoritative uncertain-outcome reconciliation;
- durable Wardveil Audit receipt ingestion and Security Center visibility;
- tested key recovery and emergency revocation procedures;
- runtime crash, replay, expiry, tamper, transport-failure, persistence-failure, executor-failure, and recovery tests.

Foundation 0.9 therefore upgrades Wardveil's source-level execution architecture without claiming that these controls are already deployed.
