# Wardveil Security Compatibility Contract

## Purpose

This contract defines how Wardveil foundation releases and machine-readable interoperability contracts relate to one another so GoreeCloud applications can detect contract drift instead of silently accepting mismatched metadata.

## Version domains

Wardveil uses separate version domains for the foundation and for individual interoperability contracts.

- `VERSION` is the authoritative Wardveil foundation release version.
- `contracts/wardveil.identity.json` must report the same `foundation_version` as `VERSION`.
- `contracts/wardveil.status.schema.json` has its own status-contract version and schema identifier.
- `contracts/wardveil.aggregation.vectors.json` has its own aggregation-contract version.
- `contracts/wardveil.runtime-authorization.json` has its own runtime authorization contract version for cross-service execution binding and replay semantics.

A foundation release may advance without changing an interoperability contract when that contract's semantics are unchanged. Consumers must therefore compare the contract version they implement, not infer contract compatibility solely from the foundation version.

## Fail-closed metadata consistency

Repository validation must fail when any of the following occurs:

- the identity contract's `foundation_version` differs from `VERSION`;
- the identity contract advertises a status-contract version different from the canonical status schema contract version;
- the identity contract advertises an aggregation-contract version different from the canonical aggregation vectors;
- the identity contract advertises a runtime authorization version different from the canonical runtime authorization contract;
- the status schema identifier does not match the expected versioned identifier;
- a required compatibility document or machine-readable contract is absent.

A metadata mismatch is treated as release drift. It must not be ignored simply because the underlying JSON still parses.

## Consumer compatibility

A consumer claiming Wardveil compatibility must record the exact contract version it implements and must reject or explicitly downgrade unsupported versions. Consumers must not interpret an unknown future version as equivalent to the version they were built against.

Backward-compatible additions may be accepted only when the relevant contract permits them. The current Wardveil status schema uses `additionalProperties: false`; therefore unrecognized fields are not implicitly compatible with status contract 0.1.0.

For runtime authorization, an executor must reject an unsupported authorization version, signature algorithm, or binding set. An unknown future runtime authorization contract must never be treated as equivalent to 0.1.0 for a high-impact action.

## Upgrade behavior

When a contract changes incompatibly, its contract version must change and all of the following must be updated together:

1. the canonical contract or schema;
2. machine-readable identity metadata;
3. conformance examples, vectors, or executable reference tests;
4. repository validation;
5. adoption and integration guidance when behavior changes;
6. the Wardveil changelog.

## Security boundary

Compatibility handling does not transfer technical authority to Wardveil, weaken fail-closed protection claims, or allow an executor to infer authorization from version compatibility alone. Runtime authorization remains separate from the underlying target system's own execution authority and production deployment acceptance.
