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

## Recommended integration layout

1. Collect state from the authoritative local control.
2. Normalize it in a small adapter owned by the consuming project.
3. Validate the normalized record against the Wardveil contract.
4. Apply freshness and scope rules.
5. Render the result through Glaze UI.
6. Keep detailed operational diagnostics in the owning system, not in the shared Wardveil payload.

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

## Remediation links

Wardveil may direct an authorized user to an application's existing remediation workflow. The link must not imply that Wardveil performed the remediation. Generic cross-service execution is outside the Wardveil 0.7 foundation contract.

## Adoption evidence

Before a project claims Wardveil integration, its repository should contain:

- a short Wardveil integration document;
- tests for protected and non-passing states;
- tests for stale or missing evidence;
- tests confirming sensitive fields are not emitted;
- a source-level or rendered accessibility check for state labels;
- exact-revision CI evidence for the integration change.

For compact or wearable surfaces, adoption evidence must additionally demonstrate that constrained rendering preserves normalized state, required freshness meaning, authority/scope discoverability, and fail-closed handling without exposing additional sensitive evidence.

Manual visual acceptance is required when the canonical Wardveil icon is used in a new target form factor; icon presence never substitutes for status semantics or runtime evidence.
