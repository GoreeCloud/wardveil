# Wardveil Security Adoption Requirements

Wardveil integration is complete only when a GoreeCloud application or service satisfies the requirements below. Branding alone is not adoption.

## Required integration contract

A consumer must:

- identify the authoritative producer for each presented security state;
- use the canonical Wardveil status semantics without inventing passing aliases;
- fail closed when required evidence is missing, stale, unavailable, incomplete, or unverified;
- bind every protection claim to an explicit scope;
- preserve evidence timestamps and freshness meaning;
- minimize shared evidence and exclude reusable secrets, credentials, private keys, recovery material, unrestricted diagnostics, and unnecessary personal data;
- keep Wardveil presentation separate from authentication, authorization, firewall, VPN, backup, vulnerability-management, and application-specific enforcement authority;
- render Wardveil through Glaze UI with text labels and accessible non-color-only state communication;
- provide a safe `unknown` experience instead of hiding unavailable security state;
- document rollback or removal of the Wardveil adapter without disabling the underlying security control.

When a consumer or executor participates in a high-impact cross-service Wardveil action, it must also:

- implement the exact runtime authorization contract version it accepts;
- reject unsupported authorization versions or signature algorithms;
- validate the authoritative policy record and its exact digest binding;
- require exact action, target scope, executor identity, correlation, expiry, nonce, and idempotency binding;
- reject expired, future-dated, tampered, policy-detached, or conflicting-replay authorization;
- preserve its own local action/resource permission checks after Wardveil authorization succeeds;
- make retries idempotent and persist replay/idempotency state with durability appropriate to the executor scope;
- emit auditable execution evidence without embedding signing secrets or reusable credentials.

## Recommended integration layout

1. Collect state from the authoritative local control.
2. Normalize it in a small adapter owned by the consuming project.
3. Validate the normalized record against the Wardveil contract.
4. Apply freshness and scope rules.
5. Render the result through Glaze UI.
6. Keep detailed operational diagnostics in the owning system, not in the shared Wardveil payload.
7. For high-impact cross-service execution, validate Wardveil runtime authorization before invoking the local executor.
8. Persist the resulting protection action and audit evidence through the owning authoritative path.

## Aggregated security views

A dashboard may combine multiple Wardveil records, but aggregation must remain conservative. A summary cannot be `protected` when any required component is `unknown`, `degraded`, or otherwise non-passing. The dashboard must allow the operator to identify which source and scope caused the summary state.

## Compact and wearable presentation

Wardveil may appear on compact, glanceable, wearable, notification, tile, complication, or similarly constrained Glaze UI surfaces, but reduced space does not reduce evidence requirements.

A constrained presentation must:

- preserve the normalized state in text or an equivalent accessible semantic instead of relying on iconography or color alone;
- preserve whether the represented evidence is current, stale, unavailable, or unverified whenever freshness materially affects the claim;
- preserve the represented scope and authoritative source through the immediately visible surface or an accessible focused detail path;
- show `unknown`, `attention`, or `degraded` honestly rather than hiding the state to simplify the layout;
- never display `Protected by Wardveil` when the full underlying record would not authorize that claim;
- avoid moving raw diagnostics, secrets, identifiers, or sensitive evidence onto a wearable merely to provide more detail;
- use a focused deep link to the authoritative owning application when remediation or detailed evidence cannot safely fit on the constrained surface;
- follow the current Stable Glaze UI contract for the target form factor before the consuming application may claim production conformance.

A compact Wardveil card is a view of an existing evidence-backed record. It does not create a new security state, broaden the producer's authority, or substitute for application-specific runtime acceptance.

## Remediation and execution

Wardveil may direct an authorized user to an application's existing remediation workflow. For cross-service technical execution, Wardveil Foundation 0.9 defines a bounded runtime-authorization contract rather than a generic unrestricted command channel.

A policy decision alone is not execution authority. The runtime authorization must be cryptographically bound to the exact decision and intended executor, and the executor must still independently possess authority for the requested action and target resource. Invalid authorization fails closed. A valid authorization does not imply that production cryptography, transport, durable replay state, or audit persistence has been accepted.

## Adoption evidence

Before a project claims Wardveil integration, its repository should contain:

- a short Wardveil integration document;
- tests for protected and non-passing states;
- tests for stale or missing evidence;
- tests confirming sensitive fields are not emitted;
- a source-level or rendered accessibility check for state labels;
- exact-revision CI evidence for the integration change.

For an executor using runtime authorization, adoption evidence must additionally include tamper, expiry, action/scope/executor mismatch, nonce conflict, idempotent retry, unauthorized executor, and execution-failure tests. Production acceptance requires deployed evidence for key management, authenticated transport, durable replay/idempotency storage, executor authentication, audit persistence, and rotation/revocation procedures.

For compact or wearable surfaces, adoption evidence must additionally demonstrate that constrained rendering preserves normalized state, required freshness meaning, authority/scope discoverability, and fail-closed handling without exposing additional sensitive evidence.

Manual visual acceptance is required when the canonical Wardveil icon is used in a new target form factor; icon presence never substitutes for status semantics or runtime evidence.
