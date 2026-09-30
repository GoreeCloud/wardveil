# Wardveil Security Compatibility Contract

## Purpose

This contract defines how Wardveil foundation releases and machine-readable interoperability contracts relate to one another so GoreeCloud applications can detect contract drift instead of silently accepting mismatched metadata.

## Version domains

Wardveil uses separate version domains for the foundation and for individual interoperability contracts.

- `VERSION` is the authoritative Wardveil foundation release version.
- `contracts/wardveil.identity.json` must report the same `foundation_version` as `VERSION`.
- `contracts/wardveil.status.schema.json` has its own status-contract version and schema identifier.
- `contracts/wardveil.aggregation.vectors.json` has its own aggregation-contract version.
- `contracts/wardveil.runtime-authorization.json` has its own runtime authorization contract version for cross-service execution binding, signing-key identity, and replay semantics.
- `contracts/wardveil.service-identity.json` has its own service-identity/key-lifecycle contract version for issuer/executor capability binding, key selection, rotation, retirement, and revocation.
- `contracts/wardveil.execution-state.json` has its own durable execution-state contract version for replay/idempotency claims, uncertain-outcome handling, and execution receipts.

A foundation release may advance without changing an interoperability contract when that contract's semantics are unchanged. Consumers must therefore compare the contract version they implement, not infer contract compatibility solely from the foundation version.

## Fail-closed metadata consistency

Repository validation must fail when any of the following occurs:

- the identity contract's `foundation_version` differs from `VERSION`;
- the identity contract advertises a status-contract version different from the canonical status schema contract version;
- the identity contract advertises an aggregation-contract version different from the canonical aggregation vectors;
- the identity contract advertises a runtime authorization version different from the canonical runtime authorization contract;
- the identity contract advertises a service-identity version different from the canonical service-identity/key-lifecycle contract;
- the identity contract advertises an execution-state version different from the canonical execution-state contract;
- the status schema identifier does not match the expected versioned identifier;
- a required compatibility document or machine-readable contract is absent.

A metadata mismatch is treated as release drift. It must not be ignored simply because the underlying JSON still parses.

## Consumer compatibility

A consumer claiming Wardveil compatibility must record the exact contract version it implements and must reject or explicitly downgrade unsupported versions. Consumers must not interpret an unknown future version as equivalent to the version they were built against.

Backward-compatible additions may be accepted only when the relevant contract permits them. The current Wardveil status schema uses `additionalProperties: false`; therefore unrecognized fields are not implicitly compatible with status contract 0.1.0.

For runtime authorization, an executor must reject an unsupported authorization version, signature algorithm, signing-key binding, or binding set. An unknown future runtime authorization contract must never be treated as equivalent to 0.1.0 for a high-impact action.

For service identity and signing-key lifecycle, an issuer/verifier must reject unknown contract semantics rather than treating an unknown identity state, capability, key state, or algorithm as trusted. A revoked or unknown key must never be interpreted as a retired-but-still-valid key, and a suspended or revoked service identity must never be interpreted as active.

For durable execution state, an executor or persistence adapter must reject an unsupported claim/receipt contract version instead of resetting, ignoring, or reinterpreting pending state. Unknown future state must never be treated as permission to retry an uncertain side effect.

## Upgrade behavior

When a contract changes incompatibly, its contract version must change and all of the following must be updated together:

1. the canonical contract or schema;
2. machine-readable identity metadata;
3. conformance examples, vectors, or executable reference tests;
4. repository validation;
5. adoption and integration guidance when behavior changes;
6. the Wardveil changelog.

Signing-key rotation does not require a contract-version change when contract semantics are unchanged. Key IDs and validity metadata are runtime identities, not contract versions. Conversely, changing the meaning of active/retired/revoked states, capability requirements, signature-binding fields, or verification semantics is a contract change and must follow the compatibility process.

## Security boundary

Compatibility handling does not transfer technical authority to Wardveil, weaken fail-closed protection claims, or allow an executor to infer authorization from version compatibility alone. Runtime authorization remains separate from the underlying target system's own execution authority and production deployment acceptance.

A compatible service-identity/key-lifecycle contract does not prove that the presented service identity is active, that a key is currently trusted, or that a production secret/key-management backend is deployed. Those facts require current authoritative runtime evidence.

Durable execution-state compatibility also does not authorize a retry. A pending or unknown execution state must remain non-executable until the applicable contract can be interpreted safely or the authoritative target state is reconciled.
