# Wardveil Security Center 2.0

Status: **Next-upgrade Development candidate — source validation only**

Wardveil Security Center 2.0 is the next-upgrade user and administrative security experience. It presents Wardveil security truth, coverage, incidents, quarantine, recovery, and provenance without becoming the authority that creates those facts.

**Presentation is not authority.** Security Center may explain, organize, filter, and expose authoritative Wardveil evidence. It may not turn UI state, transport success, a policy decision, an execution request, storage health, a recovery request, or branding into proof that a security action succeeded.

## Information architecture

Security Center 2.0 exposes twelve primary areas:

1. Protection
2. Protection Coverage
3. Threats
4. Quarantine
5. Incidents
6. Sessions and Devices
7. Application Access
8. Security Policies
9. Recommendations
10. Security Evidence
11. Audit History
12. Recovery Verification

The areas are separate views over shared evidence. They do not collapse security state, protection coverage, action authority, evidence validity, or recovery authority into one global protected flag.

## Why this status?

Every meaningful status must support a first-class **Why this status?** explanation containing the current normalized state, represented scope, coverage state, reason code, authoritative producer, observation time, evidence validity, whether protective execution was requested, whether protective execution was verified, whether reconciliation remains required, a bounded human-readable summary, and a next action.

The explanation must preserve uncertainty. Missing, stale, expired, future-dated, unavailable, malformed, non-authoritative, scope-mismatched, partially accepted, or unresolved evidence must not be rewritten into reassuring language.

## Security-state projection

Security Center consumes the next-upgrade states Protected, At Risk, Action Required, Unknown, Not Covered, Degraded, Contained, Recovering, and Reconciliation Required.

A Protected presentation is permitted only when the underlying source state is Protected, evidence remains current and bounded, applicable Protection Coverage is Covered and production accepted, required protective execution is independently verified, no unresolved reconciliation exists, and the source record itself grants bounded claim authority.

If a purported Protected record does not satisfy that chain, the reference projection fails closed to Unknown with `security_center_protection_claim_unproven`. Security Center cannot repair missing evidence itself.

Unresolved execution uncertainty is surfaced as Reconciliation Required. An interface acknowledgement or reconciliation screen cannot make an uncertain action successful. The underlying authoritative execution and reconciliation records control that state.

Expired evidence remains available as historical provenance where retention permits, but it cannot justify a current protection claim.

## GLAZE UI V1.3 Stable target

Security Center 2.0 targets **GLAZE UI V1.3 / 1.3.0 Stable** at reviewed Glaze authority revision `8354308445da9ac35ced2b37a7f503a08a0aaf72`.

The immediately preceding rollback anchor is **GLAZE UI V1.2 / 1.2.0**. Migration to V1.3 does not erase V1.2 rollback provenance or convert Security Center into a conformant or production-accepted Glaze consumer without its own application evidence.

The presentation contract explicitly covers:

- Light
- Dark
- Deep Dark
- responsive layouts
- Reduced Transparency
- Reduced Motion
- Increased Contrast
- Forced Colors
- Touch Assistance
- material fallback behavior
- performance fallback behavior

Readable security evidence and explicit critical decisions must remain on sufficiently solid surfaces. Glazed material is subordinate to clarity and is appropriate only where the applicable Glaze contract permits transient navigation, command, search, control, or feedback chrome.

Color remains supplemental. Security state must remain understandable through text and other non-color cues.

## Accessibility and resilience

The source model carries explicit presentation flags for Reduced Transparency, Reduced Motion, Increased Contrast, Forced Colors, and Touch Assistance. It also records responsive, material-fallback, and performance-fallback support.

Source declarations do not prove runtime accessibility. Keyboard behavior, focus order, assistive-technology behavior, reflow, forced-color rendering, target sizing, reduced-transparency behavior, reduced-motion behavior, and other accessibility requirements require runtime and rendered validation on the actual Security Center surface.

## Rendered review and deployment gates

Work Package F requires rendered visual review, accessibility runtime review, live evidence consumption, deployment verification, and rollback verification before production acceptance.

The source reference therefore keeps all of the following false by default:

- `rendered_visual_review`
- `accessibility_runtime`
- `live_evidence_consumption`
- `deployment_verified`
- `rollback_verified`
- `runtime_validated`
- `production_accepted`
- `stable_qualified`

A source-level implementation or passing CI must not self-promote any of these states.

### Rendered visual review

Rendered visual review must cover, at minimum, representative desktop, tablet, and mobile layouts in Light, Dark, and Deep Dark, plus Reduced Transparency, Reduced Motion, Increased Contrast, Forced Colors, Touch Assistance, and constrained-performance/material fallback behavior. Review must prioritize legibility, truthful hierarchy, focus visibility, touch reachability, clear uncertainty, and usable incident/quarantine timelines over decorative material effects.

### Deployment verification

Deployment verification must bind the served Security Center to the exact reviewed source revision and current accepted evidence contracts. Successful build or preview publication is not enough to claim production deployment acceptance.

### Rollback verification

Rollback verification must prove that Security Center can return to the immediately preceding accepted presentation/runtime revision without losing or rewriting security evidence. Rollback of presentation code must not roll security state backward, revive expired evidence, or bypass current authoritative Wardveil records.

## Relationship to Work Packages A–E

Security Center 2.0 consumes rather than replaces:

- Work Package A — Security-State Engine
- Work Package B — Protection Coverage Registry
- Work Package C — Quarantine and Execution Reconciliation
- Work Package D — Incident Plane
- Work Package E — Audit and Evidence Ledger

It must preserve each package's authority, validity, scope, uncertainty, and reconciliation semantics. Security Center may correlate them for explanation, but it may not flatten conflicting or incomplete evidence into a stronger state.

## Foundation 0.9 compatibility

Foundation 0.9 remains the accepted baseline for existing Wardveil services while this next-upgrade package is a Development candidate. Existing Security Center/public-site source does not automatically become Security Center 2.0 merely because this contract exists. Explicit consumer migration, rendered review, runtime validation, deployment evidence, and rollback evidence remain required.

## Privacy and evidence minimization

Security Center explanations must remain privacy-minimized. Shared explanation surfaces must not expose reusable credentials, active tokens, private keys, signing secrets, recovery material, raw private content, raw private activity, or unrestricted diagnostic payloads merely to make a status understandable. Privacy Shield remains GoreeCloud's privacy and minimization authority.

### Administrative privacy-minimization contract

Security Center 2.0 schema version `0.2.0` requires every projected administrative security record to carry explicit privacy-minimization guarantees. The projection is rejected unless all of the following are true:

- `raw_private_content_included=false`
- `raw_private_activity_included=false`
- `reusable_credentials_included=false`
- `recovery_material_included=false`
- `unrestricted_diagnostic_payloads_included=false`
- `identifier_scope=necessary_bounded`
- `privacy_shield_review_required=true`

The privacy-minimization object rejects extension fields. Missing guarantees, a true value for any prohibited-content flag, an unbounded identifier scope, or removal of the Privacy Shield review requirement fails closed instead of being silently repaired.

Human-readable explanation fields also reject high-signal reusable-credential and raw-private-payload markers. These checks are a source contract and conformance boundary, not a content-classification engine and not proof of runtime privacy acceptance. Runtime Security Center implementations must still demonstrate that their actual data queries, logging, exports, diagnostics, and administrative views obey the same minimization rules in the target environment.

The requirement for `privacy_shield_review_required=true` preserves the authority boundary: Wardveil may enforce its own security-side minimization rules, but it may not declare broader privacy acceptance on Privacy Shield's behalf.

Everkeep remains the resilience, backup, restore, and recovery authority. Security Center may present Everkeep recovery evidence and separate Wardveil post-recovery security verification, but an Everkeep restore result alone cannot create a Protected state.

## Current acceptance boundary

This package is **source validation only**. It defines the Security Center 2.0 schema, conservative projection reference, GLAZE UI V1.3 target, complete primary information architecture, explanation contract, explicit administrative privacy-minimization contract, accessibility/presentation metadata, and fail-closed acceptance fields.

It does **not** establish rendered visual review, live next-upgrade evidence ingestion, production Security Center deployment, runtime accessibility acceptance, rollback execution, production Identity/key acceptance, Privacy Shield runtime acceptance, Everkeep production recovery integration, production acceptance, Stable qualification, or a broad Protected by Wardveil claim.
