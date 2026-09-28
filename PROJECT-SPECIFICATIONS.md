# Wardveil Security — Project Specifications

**Repository:** `GoreeCloud/wardveil`  
**Project type:** First-party shared platform security system and service family  
**Repository lifecycle declaration (legacy Contract 0.4):** `development`; canonical Contract 2.0 lifecycle reclassification remains pending and must be evidence-backed; Foundation 0.9 overall production runtime acceptance remains unaccepted  
**Version:** `0.9`  
**Repository Platform Contract generation:** `0.4` — explicit evidence-backed migration to canonical Contract `2.0` remains required  
**Current Glaze UI consumer target:** `1.6.0` Stable  
**Migration baseline:** `2ddcf03b24b65e8e8112ba6cd18f9a9c56bb0a89`  
**License:** MIT for the current repository source unless a separately governed record states otherwise  
**Canonical authority:** This file becomes the authoritative project specification once accepted on the default branch.

## Migration and precedence

This file consolidates the former root `SPECIFICATIONS.md` with the still-applicable normative requirements from Google Drive **Project Specification — Wardveil Security.docx** (file ID `1dxtkxQtMd1K0sQniMdAl9X04ptzB4KKL`).

The Drive source also contains extensive exact-revision development, deployment, consumer-validation, and provider-provenance history. Significant project history is preserved in `PROJECT-RECORD.md`; detailed implementation chronology remains in `CHANGELOGS.md`, Git history, accepted evidence, issues, and pull requests.

Current accepted repository and runtime evidence controls factual implementation claims. Historical references to older repository names, older Glaze UI targets, superseded producer pins, candidate branches, or pre-acceptance runtime states do not override current accepted evidence.

`FEATURES.md` retains durable feature-scope documentation. Current implemented and planned feature state is authoritative in `IMPLEMENTED-FEATURES.md` and `PLANNED-FEATURES.md`, with repository change history in `CHANGELOGS.md`; the retired `FEATURE-ROADMAP.md` is not an active authority.

## 1. Role and governing principle

Wardveil Security is GoreeCloud's platform-wide shared security plane for trust, security policy, protection, detection, scanning, quarantine, response, audit, security evidence, and Security Center experiences.

Wardveil is a substantive technical authority, not a badge, marketing label, antivirus skin, or presentation-only layer.

The governing principle is:

> **Wardveil must never claim more protection than GoreeCloud can prove.**

Branding, source presence, successful CI, transport success, a policy decision, a scanner response, or a favorable user-interface state does not by itself prove that protection was executed, verified, current, or production accepted.

## 2. Foundation 0.9 service model

Foundation 0.9 is composed of cooperating first-party capabilities:

- **Wardveil Trust** — evaluates identity, device, session, service, application, and contextual security evidence.
- **Wardveil Policy** — applies scoped security rules and produces explainable security decisions.
- **Wardveil Protect** — authorizes or coordinates protection actions and verifies outcomes.
- **Wardveil Detect** — produces and correlates threat, anomaly, abuse, and behavioral findings.
- **Wardveil Scan** — inspects supported files, content, packages, URLs, messages, downloads, and other payloads through replaceable engines.
- **Wardveil Quarantine** — represents non-destructive isolation and held state.
- **Wardveil Response** — coordinates containment, remediation, escalation, and security-side recovery.
- **Wardveil Audit** — preserves minimized provenance, decisions, execution outcomes, and evidence.
- **Wardveil Security Center** — provides user and administrator visibility, explanation, investigation, and controls.

These capabilities are composable rather than obligatorily linear. Wardveil must preserve the authority of the systems that own the underlying resource, identity, privacy decision, recovery operation, or external side effect.

## 3. Non-negotiable authority and security invariants

Wardveil must preserve at least these invariants:

- Trust is not authorization.
- A Policy decision is not proof that an external action executed.
- A valid Wardveil authorization does not transfer authority over the target resource.
- Target systems must independently verify the requesting executor and requested action.
- Quarantine is not deletion.
- An anomaly is not automatically proof of malicious behavior.
- Unknown, unsupported, stale, expired, malformed, conflicting, scope-mismatched, or unverified evidence must not be represented as clean or protected.
- Transport authenticity is not evidence validity, execution authority, or execution success.
- A durable execution claim is not proof that an external side effect completed.
- An uncertain high-impact external outcome requires reconciliation rather than blind retry.
- Security state and protection coverage are separate.
- Shared evidence must exclude secrets, reusable credentials, raw private content, and unnecessary identifiers.
- User-facing security claims must remain bound to current authoritative evidence.

## 4. Security state and protection coverage

Wardveil must represent security state as an evidence-backed claim rather than a visual label.

The shared state vocabulary should support, as applicable:

- Protected
- At Risk
- Action Required
- Unknown
- Not Covered
- Degraded
- Contained
- Recovering
- Reconciliation Required

A Protected state must require a complete applicable evidence chain. It must not be created from successful transport, a Policy decision, scanner success, action request, backup operation, restore operation, or user acknowledgement alone.

Protection Coverage is a separate machine-readable contract. Coverage should identify which protections are implemented, current, accepted, missing, stale, or unknown for the represented scope, including authentication, authorization, session/device trust, malware scanning, malicious-URL protection, vulnerability/security-update posture, secret protection, network exposure, runtime integrity, security-event reporting, audit coverage, and recovery-security verification.

Wardveil must prefer explicit Unknown, Not Covered, Degraded, or Reconciliation Required states over unsupported reassurance.

## 5. Evidence and claim contract

Important security claims should bind, where applicable:

- subject and resource scope;
- capability;
- security state;
- coverage state;
- producer identity;
- evidence references;
- observation time;
- evidence validity/expiration;
- policy and authorization references;
- executor identity;
- requested action;
- verified execution outcome;
- reconciliation state;
- incident/quarantine references;
- bounded reason code and explanation;
- required remediation;
- claim-authority eligibility.

Expired, superseded, environment-mismatched, or unverifiable evidence must not satisfy acceptance or protection gates.

## 6. Runtime execution authorization and durable execution state

High-impact actions require:

- explicit Policy decisions;
- short-lived execution authorization;
- exact policy-record binding;
- exact target/action/executor binding;
- service and signing-key identity;
- replay protection;
- idempotency/reconciliation material;
- durable pre-execution claim;
- target-side authorization;
- target-state verification;
- durable result receipt;
- Audit provenance.

A nonce or executor/idempotency conflict must fail closed.

If a claim exists without a verified final outcome, Wardveil must enter reconciliation-required state. It must not automatically repeat a potentially destructive or security-sensitive action.

Production cryptography, key custody, rotation/revocation, trusted verification keys, and workload identity must be accepted separately from reference-only mechanisms.

## 7. Service identity and signing-key architecture

GoreeCloud Identity remains authoritative for production identity, authentication, service identity, credential issuance, signing-key custody, verification trust, rotation, revocation, and approved cryptography.

Wardveil may consume Identity evidence and issue Wardveil-scoped runtime authorizations only within its security authority.

Production requirements include:

- authenticated service identities;
- least-privilege capability bindings;
- short credential lifetimes;
- explicit audience/scope;
- protected signing keys;
- key identifiers and bounded rotation overlap;
- immediate key/credential revocation;
- replay and clock enforcement;
- durable authorization provenance;
- emergency-revocation and recovery procedures;
- secret exclusion from source, ordinary evidence, and diagnostics.

Reference HMAC mechanisms are test-only and are not accepted production cryptography.

## 8. Scan and detection

Wardveil Scan is the stable GoreeCloud security contract; scanning engines are replaceable infrastructure beneath it.

ClamAV is the current signature-based engine for supported paths, but it must not define Wardveil's long-term Scan architecture.

A clean finding is usable only when applicable scanner health, signature freshness, evidence validity, exact content/resource binding, authenticated caller identity, replay protections, and application enforcement requirements are satisfied.

Unknown, failed, stale-signature, malformed, unsupported, or incomplete scan outcomes must not be treated as clean.

Wardveil should support normalized findings across additional security engines and detection classes as justified, including content/file analysis, malicious URLs/phishing, mail/browser protections, package/script analysis, abuse signals, and AI/tool security boundaries.

Applications should consume normalized Wardveil findings rather than independently integrating each engine.

## 9. Quarantine, Protect, and reconciliation

Quarantine is non-destructive isolation.

Release, restore, remove, delete, rescan, escalate, and recover are separate actions and require separate authorization.

A quarantine object should preserve, where applicable:

- target resource and target authority;
- initiating finding;
- Policy decision;
- execution authorization;
- executor identity;
- target-side idempotency;
- durable pre-execution claim;
- requested action;
- authoritative target readback;
- verified resulting state;
- reconciliation state;
- incident/Audit/recovery references.

Representative states may include Quarantine Pending, Isolation Requested, Isolation Executing, Verified Quarantined, Reconciliation Required, Release Pending/Released, Restore Pending/Restored, Rescan Pending, Escalated, Removal Pending/Removed, and Failed.

A successful target call without authoritative readback does not prove successful quarantine.

## 10. Incident and response model

Wardveil should maintain a first-class incident model that correlates findings, Trust changes, Policy decisions, authorizations, protection actions, quarantine objects, reconciliation, recovery, and final verification.

Representative incident states include:

- Open
- Investigating
- Containment Pending
- Contained
- Recovery Pending
- Recovering
- Verification Pending
- Resolved
- Archived

Resolution must require explicit evidence. The absence of new events is not sufficient.

Security Center should expose a normalized incident timeline that preserves uncertainty rather than flattening missing/stale evidence into a clean narrative.

## 11. Audit and security provenance

Wardveil Audit is a first-class capability, not incidental logging.

Privacy-safe records should preserve, as applicable, correlation, actor/service identity, Policy/authorization identifiers, executor/signing-key identity, target scope, requested action, evidence references, execution outcome, reconciliation, observation time, evidence validity, incident, and quarantine references.

Audit data must remain minimized and must avoid secrets, reusable credentials, private content, and unrestricted diagnostics.

Security Center should translate this provenance into understandable explanations rather than relying on raw logs as the primary experience.

## 12. Security Center

Security Center is the primary user and administrative experience for Wardveil security state.

Primary areas should include:

- Protection
- Protection Coverage
- Threats
- Quarantine
- Incidents
- Sessions and Devices
- Application Access
- Security Policies
- Recommendations
- Security Evidence
- Audit History
- Recovery Verification

Every important state should support a first-class **Why this status?** explanation covering current state, scope, coverage, producer, observation/freshness, policy/authorization basis, requested/verified execution, uncertainty/reconciliation, and recommended next action.

Unavailable or expired evidence must remain visibly stale, incomplete, degraded, unknown, or action-required rather than silently appearing current.

Security Center and embedded Wardveil surfaces must use the current accepted Stable Glaze UI contract and meet application-specific accessibility, rendered visual, performance, responsive, reduced-motion/transparency, rollback, provenance, and deployment acceptance requirements.

Current source targets Glaze UI 1.6.0, but whole-application acceptance remains incomplete.

## 13. Privacy Shield boundary

Privacy Shield remains authoritative for privacy, consent, data minimization, data governance, transparency, and user control.

Wardveil may consume or present sanitized Privacy Shield information only when necessary and authorized for the security purpose.

Privacy effects and security effects must preserve separate capability namespaces, evidence, state semantics, authority attribution, user-facing claims, and acceptance boundaries.

Security observability must not become surveillance.

A Privacy Shield source-provenance record, transport receipt, or status record cannot transfer privacy authority to Wardveil or create Protected by Wardveil authority.

## 14. Everkeep recovery boundary

Everkeep remains authoritative for backup, restoration, recovery verification, preservation, portability, succession, and legacy.

The intended compromise/recovery flow is:

`Wardveil detects/contains → Everkeep restores → Everkeep verifies recovery → Wardveil verifies security of the restored environment`

A backup or restore operation does not independently establish Wardveil Protected state.

Wardveil recovery verification should support outcomes such as Verified Safe, Unsafe, Unknown, and Reconciliation Required, while preserving normal protection-state requirements separately.

## 15. GoreeCloud Mesh boundary

GoreeCloud Mesh is a transport/coordination path, not Wardveil security authority.

Mesh may deliver bounded evidence/events, coordinate refresh, preserve correlation, and support authenticated service communication.

Mesh must not manufacture evidence, upgrade Wardveil state, extend evidence validity, create Protected state, treat delivery as execution, grant execution authorization, or replace target/resource authorities.

Transport authenticity, evidence validity, authorization, execution authority, and execution success remain separate.

## 16. Integral Platform Systems

Wardveil must evaluate all nine Integral Platform Systems. The repository currently retains Contract 0.4 semantics until an explicit evidence-backed migration to canonical Platform Contract 2.0 is completed; lifecycle values must not be mechanically translated.

Current repository truth is recorded in `goreecloud.platform.yaml`. Source presence, a badge, or a declaration does not satisfy runtime acceptance.

Current accepted source remains incomplete for Manager, Privacy Shield runtime/provider acceptance, Everkeep production recovery, final Glaze UI consumer acceptance, live Mesh routing/delivery, production Identity/key custody, GoreeCloud Policy integration, and GoreeCloud Observability integration.

Wardveil itself is the Wardveil Security authority, so a separate Wardveil-to-Wardveil integration is not applicable.

## 17. Application integration profiles and adoption

Each GoreeCloud application/service integrating Wardveil should maintain a machine-readable or equivalently authoritative profile containing:

- consumer identity;
- supported Wardveil contract version;
- required/optional capabilities;
- protected target types;
- authorized security actions;
- Trust/Identity dependencies;
- coverage categories;
- expected evidence sources and freshness;
- offline/degraded behavior;
- Security Center surfaces;
- recovery behavior;
- adoption lifecycle state;
- known gaps and remediation owner.

The adoption lifecycle is:

`Planned → Implemented → Source Validated → Runtime Validated → Production Accepted`

Declared support does not satisfy runtime or production acceptance.

## 18. Reliability, telemetry, and privacy-safe observability

Wardveil must define capability-specific behavior when dependencies are slow, unavailable, partitioned, stale, or inconsistent.

Security-sensitive authorization/protection operations should fail closed when required authority cannot be verified. Read-only surfaces may degrade only when stale/incomplete state is clearly labeled.

Use bounded retries, dependency timeouts, replay prevention, idempotency/reconciliation, clock-skew handling, and isolation/circuit-breaking where appropriate.

Security telemetry should be purpose-limited and favor local-first processing, structured reason codes, privacy-minimized target references, explicit retention classes, and redaction of credentials, secrets, tokens, message/document content, and unnecessary personal data.

Security evidence must remain separate from product analytics.

## 19. Verification and acceptance

A traceable verification matrix should map each material requirement to automated tests, exact-runtime evidence, or an approved manual procedure.

Coverage should include:

- component/unit correctness;
- schema/contract compatibility;
- Policy/obligation enforcement;
- authorization signature/audience/scope/expiry/replay/revocation;
- service-identity/key rotation;
- concurrency and idempotency;
- dependency failure and reconciliation;
- detection/engine replacement;
- quarantine and related actions;
- recovery/Everkeep coordination;
- evidence durability/redaction/provenance;
- Security Center stale-data explanations;
- Glaze UI accessibility and supported appearance modes;
- deployment, rollback, and exact-head verification;
- Privacy Shield/data-minimization boundaries.

Source validation is not runtime acceptance. Production acceptance requires exact-environment evidence for the complete applicable control path and failure behavior.

## 20. Compatibility, migration, and rollback

Wardveil contracts must use explicit versioning, compatibility rules, migration policy, and deprecation windows.

Application/capability migration should support explicit legacy, dual-compatible, migrated, blocked, and retired states.

Compatibility adapters may translate formats but must not manufacture capabilities that the runtime does not provide.

Rollback must preserve Audit history, incidents, quarantine objects, reconciliation state, evidence provenance, and authorization safety.

A rollback must not erase security state merely to restore availability.

## 21. Operational administration and runbooks

Production runbooks should cover, at minimum:

- compromised service identity;
- signing-key compromise/emergency revocation;
- credential/replay incident;
- Policy outage/inconsistent state;
- uncertain Protect execution;
- quarantine reconciliation;
- malware-engine/intelligence failure;
- high-volume false positive;
- Security Center evidence gap;
- Audit durability incident;
- Everkeep restore followed by failed Wardveil verification;
- application-integration rollback;
- repository-governance failure;
- emergency containment and controlled recovery.

Administrative overrides must be exceptional, scoped, time-bounded, reasoned, and audited. An override must not make the interface claim Protected when required protection is bypassed.

## 22. Repository governance

Wardveil's default `main` branch must be protected by branch protection or an equivalent ruleset.

The target model requires pull-request integration, required Wardveil validation, current-head checks, controlled review, CODEOWNERS where applicable, force-push restrictions, branch-deletion restrictions, bounded administrative bypass, and governance verification.

Source-controlled safeguards do not substitute for live GitHub enforcement.

GitHub reports `main` protected and requires the `Validate Wardveil foundation` status context for everyone. The connected GitHub App cannot read the complete classic branch-protection settings, so issue #34 remains open only for final UI readback of review, conversation-resolution, force-push/deletion, and administrator/bypass details.

## 23. Current accepted implementation boundary

Accepted `main` at `2ddcf03b24b65e8e8112ba6cd18f9a9c56bb0a89` contains substantial Foundation 0.9 source/reference contracts, exact-revision validation, deployed Scan integration records, single-host durable execution/replay behavior, current Security Center Glaze UI 1.6.0 source mapping, minimized Privacy Shield interoperability/provenance contracts, production-persistence qualification contracts, public-repository governance hardening, fail-closed authority-bearing timestamp handling, and repository-native implemented/planned feature authority.

The independently accepted deployed Wardveil Scan component remains distinct from repository `main`; the active Drive specification records deployed Scan runtime revision `95e2d8cae5d317e7dfd96e74ca6ef7fcdddf28d4` and ClamAV scanner revision `1f267f3bf7024dcc8b99988b3a452d8eaed9550b`.

This evidence does **not** establish platform-wide production protection, general Protected/Covered authority, production Identity/key custody, accepted distributed persistence, accepted production quarantine execution/readback, accepted Privacy Shield provider/runtime state, accepted Everkeep production recovery, final Security Center application acceptance, release publication, or Stable qualification.

PR #175 public-repository governance hardening is integrated as `a0f149012711932442d478a69ca31bd0d81b579a`; PR #174 fail-closed timestamp hardening is integrated as `8f372f26a49f0d3448dbae56acff02c124c31c6d`; and PR #179 repository-native feature tracking is integrated as current `main` `2ddcf03b24b65e8e8112ba6cd18f9a9c56bb0a89`. Former PR #172 was closed as superseded and is not a pending source-provenance integration.

## 24. Longer-term direction

Wardveil's long-term direction is a complete GoreeCloud shared security plane:

`Trust → Policy → Detect → Scan → Protect → Quarantine → Response → Audit → Recovery Verification → Security Center`

The next major upgrade should formalize stronger security-state, coverage, incident, quarantine, normalized finding, authorization, evidence, and Security Center contracts through staged rollout:

1. Contract Freeze
2. Source Implementation
3. Runtime Observation
4. Bounded Enforcement
5. Recovery and Reconciliation Acceptance
6. Security Center Acceptance
7. Production Acceptance

Unaccepted capabilities must remain visibly unaccepted.

## Related repository documentation

- [README.md](README.md)
- [PROJECT-RECORD.md](PROJECT-RECORD.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
- [CAPABILITIES.md](CAPABILITIES.md)
- [FEATURES.md](FEATURES.md)
- [IMPLEMENTED-FEATURES.md](IMPLEMENTED-FEATURES.md)
- [PLANNED-FEATURES.md](PLANNED-FEATURES.md)
- [REPOSITORY-GOVERNANCE.md](REPOSITORY-GOVERNANCE.md)
- [SECURITY.md](SECURITY.md)
- [PRIVACY POLICY.md](PRIVACY%20POLICY.md)
- [CHANGELOGS.md](CHANGELOGS.md)
- [goreecloud.platform.yaml](goreecloud.platform.yaml)
