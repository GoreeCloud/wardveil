# Wardveil Security — Implemented Features

> **Authority:** Repository-native implemented-feature record. Verified repository source and acceptance evidence remain controlling.

## Verified Foundation 0.9 source state

The repository README identifies **Foundation 0.9 active** and currently documents the following source-level capabilities:

- replay-resistant runtime execution authorization;
- durable execution-state and reconciliation safeguards;
- explicit service identity and signing-key lifecycle;
- a bounded source-level Quarantine executor path;
- an exact-revision Cloudflare deployment gate preserving explicit target authority and least privilege;
- Wardveil-native trust, policy, protection, detection, scan, quarantine, response, audit, and Security Center contracts/semantics as scoped by the repository.

## Detection Engine V1 — Development source foundation

A bounded reference correlation layer now preserves exact resource scope, evidence provenance, freshness, explainability, and a non-authorizing incident-candidate boundary. It remains Development source only; runtime integration and production acceptance are separate gates.

## Incident Center V1 — Development review-intake foundation

A bounded Detection Engine → Incident Center review layer now converts fresh single-resource `incident_candidate` assessments into deterministic, explainable `review_required` cases. It rejects authority contamination, mixed-resource input, duplicate assessments, invalid confidence, unsupported categories, and inconsistent candidate/correlation claims; excludes stale/future/non-candidate assessments; and fixes incident, execution, containment, and production authority to false. Real incident creation and response continue through the existing authorized Incident/Response path.

## GoreeCloud Policy v1 — bounded source adoption

Wardveil now has a pure source adapter pinned to GoreeCloud Policy revision `46071886da37a6566b69cc923005eef64cce2bcc`. It constructs exact Policy v1 evaluation requests, validates complete decision evidence and provenance, rejects sensitive context recursively, treats stale decisions as unusable, and fixes execution/protection/production authority to false. Live Policy transport, caller identity, distribution, obligations coordination, target-environment evidence, and production acceptance remain separate gates.

## GoreeCloud Observability v1 — bounded source adoption

Wardveil now has a privacy-minimized operational-signal constructor pinned to GoreeCloud Observability revision `a7f6a65f442d3e517baddbe7b6ce7c250d142c8c`. It preserves all nine Observability states, explicit collection gaps, timezone-qualified evidence ordering, TTL bounds, and fail-closed privacy minimization without publishing telemetry or manufacturing healthy state. Live publication, producer authentication, retention/deletion, diagnostics/alerting, target-environment evidence, and production acceptance remain separate gates.

## GoreeCloud Manager — Security State v2 source compatibility

Wardveil's existing Security State v2 producer is source-compatible with GoreeCloud Manager's bounded read-only consumer. Manager pins Wardveil revision `9b41040ed48037451e660e860908316732384282`, and the pinned schema blob is byte-identical to the current Wardveil Security State v2 schema. This establishes source compatibility only; live producer authentication, delivery/refresh, target-environment evidence, and production acceptance remain open.

## Cloudflare liveness and readiness source interfaces

The deployable Wardveil persistence Worker exposes `/healthz` for liveness and `/readyz` for readiness. The readiness path exercises the Durable Object binding and bounded schema/storage health path rather than treating process reachability as readiness. Both endpoints are non-mutating, return privacy-safe bounded status, and do not create Wardveil protection or execution authority.

## Canonical Everkeep restore-verification consumer

Wardveil has a bounded Everkeep v1.1 restore-verification consumer tied to canonical `GoreeCloud/everkeep`. The accepted schema blob is verified unchanged between its introduction revision and current canonical Everkeep main. The consumer fails closed on stale, malformed, mismatched-revision, non-authoritative, incomplete, or authority-transferring recovery evidence.

## Acceptance boundary

Production cryptography, key management, authenticated runtime transport, production executor evidence, production deployment, cross-system runtime acceptance, Covered/Protected claims, and Stable status remain separate evidence-gated work. A Wardveil policy decision is not automatically execution authority, and branding or documentation alone is never protection evidence.
