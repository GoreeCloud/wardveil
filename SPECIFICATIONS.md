# Wardveil Security — Repository Specifications

## Product

**Name:** Wardveil Security by GoreeCloud  
**Short name:** Wardveil  
**Repository:** `GoreeCloud/goreecloud-wardveil`  
**Lifecycle:** Development  
**Current architecture baseline:** Foundation 0.9  
**Planned major target:** Wardveil 2.0 — Adaptive Security & Trust  
**Platform Contract:** 0.4  
**Current Glaze UI consumer target:** 1.6.0 Stable

## Purpose

Wardveil Security is GoreeCloud’s platform-wide shared security plane for trust, security policy, protection, detection, scanning, quarantine, response, audit, security evidence, and user/administrator security experiences.

Wardveil is a substantive technical authority. Branding, source presence, CI success, or a favorable user-interface state does not by itself prove that a protection is deployed, current, or production accepted.

## Scope

The repository owns Wardveil security contracts, reference and Development implementations, shared security semantics, evidence schemas, validation, security-state models, Scan integration boundaries, execution authorization/state controls, and Security Center source.

Authoritative applications, services, identity systems, network controls, operating systems, scanners, recovery systems, and target executors retain authority over their own underlying state and actions.

## Architecture

The Foundation 0.9 model consists of:

- **Trust** — evaluates identity, device, session, service, application, and contextual evidence;
- **Policy** — applies scoped security rules and produces explainable decisions;
- **Protect** — authorizes or coordinates protection actions and verifies outcomes;
- **Detect** — produces and correlates threat, anomaly, abuse, and behavior findings;
- **Scan** — inspects supported content through replaceable engines;
- **Quarantine** — represents non-destructive isolation state;
- **Response** — coordinates containment, remediation, and security-side recovery;
- **Audit** — records minimized provenance, decisions, execution outcomes, and security evidence;
- **Security Center** — presents bounded user and administrator security state.

Components may be composed in different flows. The architecture must preserve domain authority rather than forcing every operation through one monolithic service.

## Security Invariants

- Trust is not authorization.
- A Policy decision is not proof of target execution.
- A Wardveil authorization does not transfer target-resource authority.
- Target systems must validate the requesting executor and action.
- Quarantine is not deletion.
- An anomaly is not automatically proof of malicious behavior.
- Unknown, stale, malformed, unsupported, conflicting, or unverified evidence must not be shown as clean or protected.
- Transport authenticity is not evidence validity.
- Durable execution claims are not proof of external side effects.
- Uncertain external outcomes require reconciliation rather than blind retries.
- Security state and protection coverage are separate.
- Shared evidence must exclude secrets, reusable credentials, raw private content, and unnecessary identifiers.

## Functional Requirements

Wardveil must support, as applicable to the implementation stage:

1. evidence-backed trust evaluation;
2. scoped security-policy decisions;
3. authorized protection-action execution and target-state verification;
4. threat and anomaly detection;
5. replaceable malware/content scanning;
6. non-destructive quarantine and separately authorized mutations;
7. incident grouping and lifecycle management;
8. minimized security audit/evidence records;
9. service-identity and signing-key lifecycle boundaries;
10. replay/idempotency and execution reconciliation;
11. protection-coverage and gap reporting;
12. recovery coordination with Everkeep;
13. privacy-authority separation with Privacy Shield;
14. user and administrator security experiences through Security Center.

Planned Wardveil 2.0 adaptive-security capabilities remain planned or Development-bounded unless exact implementation and runtime evidence establishes otherwise.

## Data and Storage

Security records must be minimized and purpose-limited. Reusable secrets, raw private content, and unnecessary identifiers must not be stored in ordinary evidence.

Current source includes single-host durable execution-state behavior and Development storage models. Production storage must provide accepted durability, concurrency behavior, integrity, recovery, retention, access control, and authoritative provenance.

## Authentication and Authorization

GoreeCloud Identity remains authoritative for production identity, issuance, authentication credentials, JWKS trust, and key custody.

Wardveil may consume Identity evidence and issue security-domain runtime authorizations within its scope, but those authorizations must remain short-lived, exact-action/target/executor bound, and independently verified by the target authority.

Reference HMAC mechanisms are test-only and are not approved production cryptography.

## Privacy

Privacy Shield remains authoritative for privacy and data-use authorization. Wardveil may produce security evidence relevant to privacy decisions but must not replace Privacy Shield authority.

Security evidence must be sanitized and minimized before crossing boundaries that do not require raw details.

## Scan and Detection

Wardveil Scan must keep the scanning engine replaceable. ClamAV is the current engine beneath supported Scan paths, not the definition of Wardveil.

Unknown, failed, stale-signature, malformed, or unsupported scan outcomes must not be treated as clean.

## Quarantine and Response

Quarantine must preserve non-destructive isolation semantics. Release, restore, removal, deletion, and other mutations require separate authorization and outcome verification.

Response must preserve evidence where necessary and must distinguish requested action, execution claim, verified outcome, and unresolved reconciliation.

## Backup, Recovery, and Resilience

Everkeep remains the recovery authority. Wardveil must:

- define the durable state that requires backup;
- preserve replay/reconciliation, policy, incident, quarantine, and audit integrity across restore;
- exclude reusable secrets from ordinary evidence/backup exports unless governed secret recovery explicitly requires them;
- verify restored security-sensitive state before normal operation resumes;
- provide rollback/recovery procedures for material deployments.

Current accepted Everkeep production integration remains incomplete.

## Accessibility and Interface Requirements

Security Center and Wardveil-facing interfaces must use the current Stable Glaze UI contract, provide keyboard and assistive-technology support, avoid color-only security meaning, maintain readable status/explanations, and support reduced-motion/transparency fallbacks where applicable.

Security Center source/build migration to Glaze UI 1.6.0 is integrated. Final rendered review, representative accessibility/performance validation, rollback, deployed-byte/provenance, consumer-registry, deployment, runtime, and production acceptance remain required.

## Platform Integrations

Wardveil must evaluate all nine GoreeCloud Integral Platform Systems under Platform Contract 0.4. Current integration states are recorded in `goreecloud.platform.yaml`. GoreeCloud Sync remains separately governed.

No platform-system badge, declaration, or source contract may be used as a substitute for required runtime acceptance.

## Deployment and Observability

Production deployment must be exact-revision traceable, private by default, fail closed where protection authority is unavailable, and observable without unnecessary sensitive-data collection.

GoreeCloud Observability integration is currently blocked pending accepted central contracts and Wardveil-specific operational evidence.

## Testing and Validation

Material changes require exact-head validation appropriate to their scope. Tests must cover success, malformed/unknown state, expiry/freshness, replay/idempotency, authorization mismatch, evidence conflict, failure handling, and recovery where applicable.

CI success is source evidence only unless a separate runtime/deployment acceptance gate explicitly says otherwise.

## Production Acceptance

Wardveil may claim production protection only when the exact candidate has:

- accepted Identity/key custody and approved cryptography;
- accepted target execution/readback for represented actions;
- current evidence freshness and coverage;
- accepted Privacy Shield, Everkeep, Glaze UI consumer acceptance, Mesh, Manager, Policy, Observability, and other applicable platform-system integrations;
- deployment, rollback, monitoring, recovery, and security validation;
- exact release-candidate identity and complete Stable blockers where Stable is claimed.

## Current Implementation Boundary

Foundation 0.9 and next-upgrade source contracts/reference models are substantial Development evidence. They do not establish platform-wide production protection, Protected/Covered state, release publication, or Stable status.

Use `CAPABILITIES.md`, `FEATURE-ROADMAP.md`, `goreecloud.platform.yaml`, and current exact-revision evidence for current capability and gate status.
