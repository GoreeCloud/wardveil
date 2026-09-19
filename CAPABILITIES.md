# Wardveil Security — Capabilities

## Overview

Wardveil Security is GoreeCloud’s platform-wide security, protection, trust, detection, verification, policy, response, and security-evidence authority.

This record describes the current verified repository capability state. Wardveil remains **Development**. Source implementation, contracts, reference engines, validators, and exact-revision tests do not by themselves establish deployed protection coverage, production acceptance, Protected/Covered status, release status, or Stable qualification.

## Core Capabilities

### Foundation 0.9 security plane

Current source defines and validates the Wardveil Foundation 0.9 service model:

- Wardveil Trust for evidence-backed trust-state evaluation;
- Wardveil Policy for scoped security decisions;
- Wardveil Protect for authorized protection-action coordination and outcome verification;
- Wardveil Detect for structured security findings and correlation;
- Wardveil Scan for replaceable inspection engines;
- Wardveil Quarantine for non-destructive isolation state;
- Wardveil Response for containment and remediation coordination;
- Wardveil Audit for minimized security provenance and execution evidence;
- Security Center contracts and source surfaces for user and administrator security experiences.

These capabilities are composable. A Trust result is not authorization, a Policy decision is not proof that a target action executed, and a Wardveil authorization does not transfer authority over a target resource.

### Security-state and coverage models

Current Development source includes:

- next-upgrade security-state models;
- evidence freshness and conflict handling;
- fail-closed protection claims;
- a Protection Coverage Registry;
- capability- and consumer-scoped coverage states;
- remediation/gap visibility;
- exact-evidence binding.

Missing, stale, malformed, unsupported, or conflicting evidence must not be converted into a protected state.

### Runtime authorization and execution state

Wardveil source defines:

- runtime execution authorization bound to exact action, target, policy, executor, nonce, idempotency key, issue/expiry time, and signing-key identity;
- durable execution claims and receipts;
- replay/idempotency handling;
- uncertain-outcome reconciliation;
- target-state verification boundaries;
- single-host SQLite execution-state persistence;
- source-level Cloudflare Durable Object persistence adapters.

An execution claim is not proof of an external side effect. Uncertain external outcomes require reconciliation rather than blind re-execution.

### Identity and signing-key lifecycle

Current source defines first-party service-identity and signing-key lifecycle contracts, including capability checks, active/retired/revoked states, bounded rotation overlap, explicit key identifiers, and secret-exclusion boundaries.

Production GoreeCloud Identity issuance, JWKS trust, approved cryptography, production key custody, rotation/revocation operations, and runtime acceptance remain open.

### Wardveil Scan

Wardveil provides a replaceable scanning boundary. The current platform uses ClamAV beneath Wardveil Scan for supported malware inspection, while ClamAV does not define Wardveil security authority.

Current evidence includes source/runtime work for authenticated Scan transport, fail-closed stale-signature handling, replay/idempotency controls, and bounded application-consumer integration. Overall Wardveil production acceptance remains independent and incomplete.

### Quarantine, incidents, and audit

Current Development source includes:

- durable Quarantine object and transition models;
- separation of quarantine from deletion;
- explicit authorization requirements for mutations;
- incident-plane models and evidence-driven lifecycle transitions;
- normalized security events;
- containment/recovery status boundaries;
- an Audit and Evidence Ledger with minimized provenance and integrity chaining;
- explanation-ready records for Security Center.

Live production storage, target execution/readback, production retention enforcement, Security Center consumption, and full runtime acceptance remain open.

## User Capabilities

### Security Center

Security Center is Wardveil’s primary user and administrator presentation surface.

The active repository-local Security Center source remains on the historical Glaze UI 1.1.0 baseline while the current GoreeCloud consumer target is **Glaze UI 1.6.0 Stable**. Migration, rendered review, accessibility, representative-target validation, deployment/rollback verification, live evidence consumption, runtime acceptance, and production acceptance remain required.

### Explainable security state

Wardveil contracts support explanation of:

- current security state;
- protection coverage and gaps;
- evidence freshness;
- trust reasons;
- policy outcomes;
- detected findings;
- quarantine state;
- incidents and response state;
- execution outcomes and unresolved reconciliation.

User-facing state must not imply broader protection than current authoritative evidence proves.

## Administrative Capabilities

Current repository capabilities include:

- machine-readable security contracts;
- validation workflows;
- policy and execution reference implementations;
- security-evidence and Mesh delivery profiles;
- service-identity/key-lifecycle references;
- durable execution-state models;
- Scan runtime tooling;
- platform-adoption evidence;
- recovery and Everkeep handoff contracts;
- repository-side feature-roadmap controls.

These controls support governed review and administration. They do not self-grant production protection.

## Platform Integrations

The repository manifest uses Platform Contract 0.4 and evaluates all nine GoreeCloud Integral Platform Systems. GoreeCloud Sync remains separately governed.

- **GoreeCloud Manager:** applicable blocked; current accepted Manager integration is not established.
- **Privacy Shield:** applicable migration required; authority boundaries are preserved but live production Privacy Shield integration remains incomplete.
- **Wardveil Security:** not applicable as a separate consumer because this repository implements the Wardveil authority.
- **Everkeep:** applicable migration required; source-level durable state exists, but accepted Everkeep backup/restore and recovery integration remains incomplete.
- **Glaze UI:** applicable migration required; Security Center must move from historical 1.1.0 to current Stable 1.6.0.
- **GoreeCloud Mesh:** applicable migration required; minimized security-evidence delivery exists at source level, while live routing, producer identity, registry publication, and production acceptance remain open.
- **GoreeCloud Identity:** applicable migration required; production issuance/JWKS/key custody and acceptance remain open.
- **GoreeCloud Policy:** applicable blocked pending accepted central Policy runtime integration.
- **GoreeCloud Observability:** applicable blocked pending accepted operational-health, telemetry, freshness, completeness, and evidence integration.

## Data and Interoperability

Wardveil uses structured, minimized security contracts and evidence. Shared records must exclude reusable secrets, raw private content, and unnecessary identifiers.

Security state, findings, decisions, execution records, quarantine state, incidents, and audit evidence should remain attributable to the authoritative producer and exact scope.

## Supported Platforms and Interfaces

The current repository manifest declares Linux and web support at the repository foundation level.

Consumer/runtime support must be evaluated independently. A source contract or adapter does not establish a supported production runtime.

## Security and Privacy Capabilities

Current source provides:

- fail-closed evidence evaluation;
- trust/policy separation from target authorization;
- scoped short-lived execution authorization;
- replay/idempotency and reconciliation controls;
- minimized audit/evidence contracts;
- replaceable scan-engine boundaries;
- service-identity and key-lifecycle reference behavior;
- bounded Mesh evidence transport;
- Privacy Shield authority separation;
- Everkeep recovery-boundary contracts.

Production key custody, approved cryptography, live target execution, production Identity, Policy/Observability conformance, Privacy Shield acceptance, and overall production approval remain open.

## Resilience, Backup, and Recovery Capabilities

Wardveil source provides single-host durable execution-state behavior and recovery-oriented contracts. Everkeep remains the resilience authority.

Production readiness still requires accepted backup/restore, replay-state preservation, incident/quarantine/audit recovery, target-state reconciliation, rollback, and post-restore Wardveil verification.

## Accessibility Capabilities

Security Center is subject to GoreeCloud accessibility and Glaze UI requirements. Current Stable 1.6.0 migration and exact-revision rendered accessibility acceptance are incomplete, so no current production accessibility-conformance claim is made here.

## Automation and Validation Capabilities

Wardveil has automated source validation covering Foundation behavior, Platform Contract conformance, authenticated Scan transport, security-state models, Mesh evidence, trust posture, policy/execution bridging, and related contracts.

Validation is exact-revision evidence for the source scope tested. It is not a substitute for deployment, target runtime behavior, production acceptance, release, or Stable qualification.

## Current Limitations

Major open boundaries include:

- persistent production security/trust/integrity/detection/containment/credential/incident engines;
- production Identity/key custody and approved cryptography;
- live target-system execution and authoritative readback;
- accepted Privacy Shield integration;
- accepted GoreeCloud Policy and Observability integrations;
- accepted Everkeep recovery;
- Security Center migration to Glaze UI 1.6.0 and live evidence consumption;
- complete production monitoring, rollback, deployment, and release qualification;
- default-branch protection/ruleset enforcement through the centralized GitHub governance workflow.

## Capability Validation

Treat each Wardveil claim as scope-specific and evidence-backed. Bind validation to exact source revision, artifact/runtime identity, target, evidence freshness, and authoritative producer. Unknown or stale evidence fails closed. One accepted capability or consumer must not be used to infer platform-wide Wardveil protection.
