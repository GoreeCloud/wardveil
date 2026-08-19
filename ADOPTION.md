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

## Remediation links

Wardveil may direct an authorized user to an application's existing remediation workflow. The link must not imply that Wardveil performed the remediation. Generic cross-service execution is outside the 0.4 contract.

## Adoption evidence

Before a project claims Wardveil integration, its repository should contain:

- a short Wardveil integration document;
- tests for protected and non-passing states;
- tests for stale or missing evidence;
- tests confirming sensitive fields are not emitted;
- a source-level or rendered accessibility check for state labels;
- exact-revision CI evidence for the integration change.

Manual visual acceptance is additionally required when the canonical Wardveil icon is eventually approved and used.
