# Wardveil Work Package J — Policy-to-Execution Authorization Bridge

## Status

**Development / source candidate.** This work does not establish production execution authorization, target-side authority, external side-effect success, or a platform-wide Protected claim.

## Purpose

Work Package J connects the next-upgrade Policy Decision and Enforcement Contract to the existing Foundation 0.9 runtime execution-authorization, durable execution-state, Protect, Audit, and reconciliation path without inventing a competing execution-authority model.

The authoritative execution sequence remains:

`Policy decision -> short-lived execution authorization -> durable pre-execution claim -> authorized target executor -> target-state verification -> Protect receipt -> Audit -> Security Center`

A v2 Policy decision is never itself an execution authorization.

## Compatibility strategy

Foundation 0.9 already provides:

- the signed runtime execution-authorization envelope;
- exact authoritative-policy digest binding;
- short authorization lifetime;
- issuer/executor/key identity binding;
- replay nonce and idempotency identity;
- durable pre-execution claims;
- uncertain-outcome reconciliation;
- Protect result and durable execution receipts.

Work Package J therefore keeps that wire contract unchanged. The bridge derives an exact-digest-bound Foundation 0.9-compatible policy record from one valid v2 Policy decision and passes that derived record through the existing authorization issuer/verifier.

The derived record is not a new policy decision. It is a compatibility representation whose entire content is covered by the existing Foundation 0.9 `policy_digest_sha256` authorization binding.

## Fail-closed eligibility

The bridge accepts only a v2 decision that passes the existing `evaluate_policy_decision()` gate and whose outcome is:

- `allow`; or
- `allow_with_obligations`.

The following never mint execution authorization through this bridge:

- `deny`;
- `require_step_up`;
- `defer`;
- `unknown`;
- malformed decisions;
- revoked decisions;
- expired decisions;
- future-dated decisions;
- decisions whose execution boundary no longer states that separate execution authorization is required.

The requested concrete action must also be one of Foundation 0.9's high-impact protection actions. A general Policy allow is not automatically translated into a mutation.

## Exact binding

The bridge preserves and signs through the derived policy digest:

- v2 decision ID and SHA-256 digest;
- correlation ID;
- exact policy ID/version/digest;
- actor or service identity binding;
- concrete requested action;
- exact target identifier;
- purpose;
- scopes;
- audiences;
- trust state and trust evidence references;
- decision reason codes;
- obligations;
- obligation evidence references;
- decision evidence references;
- revocation state;
- execution-boundary assertions;
- validity window.

The target resource type is an explicit bridge input because the v2 Policy contract currently binds the target as an opaque exact identifier. Supplying a resource type does not grant authority over that type; the target executor must independently verify that it may perform the exact action against that target/resource type.

## Obligations

A v2 `allow_with_obligations` decision cannot cross into execution authorization until every named obligation has a non-empty evidence reference. The bridge requires exact obligation/evidence-key equality:

- missing obligation evidence fails closed;
- unexpected obligation evidence fails closed;
- empty evidence references fail closed.

The obligation names and their evidence references become part of the derived policy record and therefore part of the signed policy digest. They cannot be dropped or changed without invalidating authorization verification.

This source model treats obligations as pre-authorization gates. If a future obligation is explicitly defined as post-execution or continuously enforced, it requires a separately governed obligation lifecycle rather than weakening this bridge.

## Authorization lifetime

The bridge reuses Foundation 0.9's maximum authorization TTL and its rule that authorization may not outlive its source policy record. Because the derived record keeps the v2 decision's exact `valid_until`, a bridged authorization cannot outlive that v2 decision.

A revoked or otherwise unusable v2 decision also fails when the verifier rebuilds the bridge record at evaluation time. Previously issued authorization does not turn a subsequently revoked v2 decision into usable current authority.

## Target authority and execution evidence

A valid bridged authorization proves only that Wardveil accepted the exact bound execution request through the execution-authorization gate.

It does not prove:

- that the executor owns or controls the target;
- that the target permits the action;
- that the external action executed;
- that the external action succeeded;
- that target state matches Wardveil's intended state;
- that reconciliation is unnecessary;
- that Wardveil overall is production accepted.

The executor still needs target-side authority. Production high-impact execution still requires a durable pre-execution claim. Final state still requires authoritative target readback or equivalent verification, a Protect receipt, Audit ingestion, and appropriate Security Center visibility.

## Privacy and secrets

The bridge stores identifiers, minimized policy/trust/evidence metadata, and evidence references required for authorization provenance. It does not require raw resource content or reusable credentials.

Signing secrets, private keys, passwords, access tokens, session tokens, cookies, and raw authorization headers are prohibited from the bridge record and existing authorization envelope.

Privacy Shield remains authoritative for retention, minimization, disclosure, and other privacy constraints. Everkeep remains authoritative for recovery and continuity requirements around durable execution state and target recovery.

## Production acceptance boundary

Work Package J is source compatibility only until independent evidence exists for the exact production path, including:

- accepted production GoreeCloud Identity/service identity and key custody;
- approved signing algorithm and signer;
- authenticated authorization transport;
- deployed durable execution claims and receipts;
- an authorized target executor;
- authoritative target-state readback;
- uncertain-outcome reconciliation;
- Audit ingestion and Security Center visibility;
- Privacy Shield acceptance;
- Everkeep recovery acceptance;
- failure, replay, expiry, revocation, crash, persistence, executor, and recovery exercises.

For the current authoritative Priority 2, this bridge is preparation for real GoreeCloud Drive quarantine production acceptance; it does not itself perform or accept that production integration.
