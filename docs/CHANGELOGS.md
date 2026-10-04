# Wardveil Security — Changelogs

## 2026-10-03 — Security Center Glaze V1.7 canonical source adoption

- Reconciled the canonical Security Center source to `GoreeCloud/static-websites/sites/main/security/index.html` at exact V1.7 source revision `531744f2a82133caca8ddde00fa782415d1a42e1` and exact route blob `1c3f93866eb76c9ce366ba8f2db42b15dc5ad427`.
- Recorded successful repository/main-site validation, isolated-artifact validation, responsive browser smoke including `/security/`, and a successful Cloudflare Pages deployment check for that exact revision.
- Updated the Wardveil Platform Contract Glaze relationship from historical source target `1.6.0` to canonical source target `1.7.0` while keeping the relationship migration-required.
- Corrected the legacy website authority record to `GoreeCloud/static-websites` and preserved the Wardveil repository-local V1.6 site as transitional deployment/rollback material.
- Kept `security-center-glaze-acceptance` blocked because canonical-origin readback, human/accessibility/performance/resilience review, rollback evidence, final consumer acceptance, and legacy `security.goreecloud.com` retirement/cutover remain incomplete.
- No Wardveil runtime, protection-claim, production, Anchor, or Stable authority is created by this source reconciliation.

## 2026-10-03 — Public-history safety disposition

- Accepted the already-published bounded non-confidential repository metadata documented by issue #176 as existing public information after forward minimization of current `main` and continued fail-closed retained-reference auditing.
- Added `docs/PUBLIC-HISTORY-DISPOSITION.md` and marked only `public-history-safety` as passed.
- The other eight Version 2.0 Anchor qualification gates remain blocked, so Wardveil remains Seal and not Stable.
- Corrected current-state Project Record surfaces to identify `wardveil-2.0.0-seal.1` while preserving the September 30 Foundation 0.9 Seal transition as historical evidence.
- No branch retirement, shared-history modification, runtime authority, deployment, production acceptance, published release, Anchor, or Stable authority is created by this disposition.

## 2026-10-03 — Version 2.0 release identity and 2.0.1 scope split

- Rebased the governed Wardveil release identity from Foundation 0.9 to **Version 2.0.0** without changing the frozen implementation source: candidate `wardveil-2.0.0-seal.1` remains bound to `cc493530c02925a4404c54d2767c15d9fbfa0835`.
- Preserved Seal lifecycle, development deployment, blocked Anchor qualification, and all nine mandatory gate groups; no missing runtime, security, privacy, recovery, Glaze, observability, release, or public-history evidence is treated as passing.
- Assigned unfinished/unverified feature expansion outside the bounded 2.0 qualification boundary to **Version 2.0.1**.
- Added an explicit release-boundary record with internal/external version identity and the non-deferrable 2.0 Anchor gates.

## 2026-09-30 — Foundation 0.9 Seal candidate

- Promoted the current release line from Weave to **Seal** under Platform Contract 2.0 by freezing exact candidate `wardveil-0.9.0-seal.1` at implementation source `cc493530c02925a4404c54d2767c15d9fbfa0835` / tree `b835d305c3b21d72cd00645dac3d1945626c6d8b`.
- Added `qualification/seal-candidate.json` with exact-source validation identities and a non-authorizing candidate boundary.
- Reclassified the existing nine gate groups as blocked **Anchor qualification** gates rather than reasons to withhold exact Seal identity.
- Updated Platform Contract lifecycle metadata, repository-governance validation, Seal/Anchor readiness validation, README, project record, and planned-feature authority while preserving development deployment, blocked qualification, migration/recovery flags, unaccepted production runtime, and empty published-release evidence.
- Any material release-critical implementation/configuration change invalidates `seal.1` and requires a new Seal candidate; this transition grants no production, protection, or Anchor authority.

## 2026-09-30 — Retained public-ref inventory classification

- Extended the retained public Git history audit to classify fetched public branches and tags after the required all-branch/all-tag fetch.
- The audit now reports duplicate-tip branch groups, non-main branches whose tips are fully contained in current `main`, and non-main branches that genuinely diverge from `main`.
- Divergence reporting is evidence only: it does not delete refs, authorize branch retirement, rewrite history, or classify restricted non-secret content as safe.
- The credential-shaped secret scan remains fail closed and unchanged.

## 2026-09-30 — Status visual-identity authority reconciliation

- Reconciled `docs/STATUS.md` with the already-approved Wardveil Security **Sentinel Fold** identity and canonical GoreeCloud branding authority.
- Kept visual identity separate from technical protection evidence: approved artwork does not create or upgrade a `Protected by Wardveil` claim.
- Extended repository-governance validation to fail if pre-approval icon language returns or the status contract loses the approved canonical identity boundary.
- This documentation/governance correction does not change runtime behavior, protection acceptance, Seal, Anchor, release, or production authority.

## 2026-09-30 — Documentation-trigger stabilization

- Replaced two stale workflow path filters that still watched retired root `FEATURE-ROADMAP.md` with the canonical `docs/IMPLEMENTED-FEATURES.md` and `docs/PLANNED-FEATURES.md` records.
- Extended repository-governance validation so the policy-execution and trust-posture workflows fail closed if the retired roadmap path returns or either canonical feature-state path is omitted.
- This CI/documentation stabilization does not change runtime behavior, protection claims, provider acceptance, Seal, Anchor, release, or production authority.

## 2026-09-29 — Repository root documentation migration

- Moved Wardveil human-readable repository documentation from root into the canonical `docs/` tree under the GoreeCloud repository-root cleanliness standard.
- Added `docs/README.md` as the documentation index and reconciled README navigation, validators, workflows, Platform Contract evidence, Seal-readiness evidence, CODEOWNERS, and machine-readable contract-document paths.
- Repository governance now fails closed if migrated human documentation is reintroduced at root.
- This organization change does not grant runtime/provider acceptance, Protected by Wardveil status, Seal, Anchor, release, or production authorization.


## 2026-09-29 — Capability and lifecycle documentation reconciliation

- Reconciled `CAPABILITIES.md`, `PROJECT-RECORD.md`, and `README.md` with the authoritative Platform Contract 2.0 **Weave** lifecycle, Foundation 0.9 source/runtime line, development deployment state, blocked qualification state, and Seal next gate.
- Reconciled Manager, Policy, Observability, current Glaze UI V1.6, and private `wardveil-persistence-rpc/v1` source integration state while preserving every live runtime, recovery, deployment, protection-claim, Seal, and Anchor acceptance gate.
- Replaced an accidental literal escaped newline in the existing Seal-readiness changelog entry with real Markdown line breaks; no validation threshold or authority changed.
- Updated the repository-governance validator to bind the README to the authoritative Platform Contract 2.0 Weave lifecycle and the VERSION-derived active Foundation source/runtime line.

## 2026-09-29 — Bounded Wardveil Platform API V1 declaration

- Added a machine-readable private API contract for the already-implemented Cloudflare persistence Worker service-binding/RPC surface.
- Declared supported API version `wardveil-persistence-rpc/v1` and symbolic endpoint `service-binding://goreecloud-wardveil-persistence` in Platform Contract 2.0.
- Separated supported application RPC methods from acceptance-only retention/observability probe methods, preserved public HTTP as non-mutating `/healthz` and `/readyz`, and added exact-source CI validation.
- Corrected stale README wording that still described the public runtime boundary as `/healthz`-only.
- Production API acceptance remains unaccepted; this creates no public mutation API, deployment, Seal, Anchor, or execution/protection authority.

## 2026-09-29 — Fail-closed Seal readiness guard

- Added a machine-readable Wardveil Seal-readiness record covering the release-critical gate groups still blocking candidate freeze; the current guard now includes a ninth public-history safety gate.
- Added CI validation that keeps lifecycle at Weave with `candidate_identity: null`, requires all eight external platform-system relationships to remain migration-required until accepted, and rejects Seal/Anchor promotion while runtime/recovery/release evidence remains blocked.
- Bound the guard to the current unaccepted Cloudflare runtime contract, pending liveness/readiness/restore evidence template, canonical Everkeep restore consumer, and empty release evidence.
- Added the unresolved public-history safety disposition from issue #176 to the same promotion boundary: retained-ref credential-shaped scanning is automated/green, but restricted non-secret provenance already published in reachable history has no accepted final disposition.
- This guard does not create a Seal candidate; it prevents lifecycle metadata from outrunning real acceptance evidence.

## 2026-09-29 — Canonical Everkeep restore-verification provenance

- Re-pinned Wardveil's restore-verification consumer from the predecessor Everkeep repository identity to canonical `GoreeCloud/everkeep`.
- Verified Everkeep restore-verification v1.1 is byte-identical between introduction revision `4de9a3425215bbee5595eb929c1eb94d94d6f7b2` and current canonical main `f69e369e4d8627280fac728b7f7bcb02c43b5edd` (blob `158f2afe001be211d91ebfaa3e33c475849d53f9`).
- Added canonical source revision/blob provenance to the consumer contract and Platform Contract evidence.
- This source correction does not create a live restore exercise or production recovery acceptance.

## 2026-09-29 — Cloudflare liveness/readiness source gate

- Added a public `/readyz` endpoint to the Wardveil Cloudflare persistence Worker that exercises the Durable Object binding and bounded schema/storage health path through a dedicated non-authorizing readiness tenant.
- Kept `/healthz` as liveness-only and bounded both public endpoints to privacy-safe, non-mutating status.
- Extended the runtime-acceptance and deployment contracts so deployed readiness is a required exact-revision evidence item alongside liveness.
- Updated Platform Contract health/readiness declarations from null to `/healthz` and `/readyz` without changing production runtime status from unaccepted.

## 2026-09-29 — Manager Security State v2 source compatibility

- Reconciled the existing Wardveil Security State v2 producer with GoreeCloud Manager's bounded read-only consumer rather than creating a duplicate status contract.
- Verified Manager's pinned Wardveil Security State v2 schema blob is byte-identical to the current Wardveil schema.
- Moved Manager from source-blocked to migration-required in Platform Contract 2.0 while preserving live producer authentication, delivery/freshness, target-environment, operational, and production acceptance gates.

## 2026-09-29 — GoreeCloud Policy and Observability v1 source adoption

- Added a bounded GoreeCloud Policy v1 request/decision adapter pinned to authoritative Policy revision `46071886da37a6566b69cc923005eef64cce2bcc`.
- Added a privacy-minimized GoreeCloud Observability v1 signal adapter pinned to authoritative Observability revision `a7f6a65f442d3e517baddbe7b6ce7c250d142c8c`.
- Added fail-closed tests and source validators for sensitive context/attributes, provenance mismatch, stale Policy evidence, ambiguous timestamps, evidence ordering, collection gaps, and non-authorizing semantics.
- Reclassified Policy and Observability Platform Contract results from source-blocked to migration-required only; live runtime/production acceptance remains open.

## 2026-09-29 — Platform Contract 2.0 Weave migration

- Migrated the authoritative platform manifest from Contract 0.4 to Contract 2.0 and reclassified Foundation 0.9 from legacy Development to **Weave** based on verified convergence maturity.
- Added separate lifecycle metadata with development deployment state, blocked qualification, migration/recovery flags, next gate Seal, and no fabricated candidate identity.
- Repinned Platform Contract validation to the current Contract 2.0 evaluator revision while preserving all unresolved Manager, Privacy Shield, Everkeep, Glaze UI consumer, Mesh, Identity, Policy, Observability, runtime, recovery, and production blockers.
- This lifecycle correction does not establish Seal, Anchor, Protected/Covered status, or broad production acceptance.

## 2026-09-29 — Incident Center V1 assessment-integrity hardening

- Reject duplicate Detection Engine assessments before they can inflate review-case counts or corroboration presentation.
- Revalidate bounded confidence, supported signal categories, candidate provenance, and Detection Engine correlation/candidate invariants at the Incident Center trust boundary instead of trusting directly constructed dataclass values.
- Preserve the non-authorizing boundary: this hardening still creates only `unknown` or `review_required` intake state and grants no incident, containment, execution, Protected/Covered, deployment, or production authority.

## 2026-09-28 — Incident Center V1 development review intake

- Added a bounded Detection Engine → Incident Center review-case reference, machine-readable schema, tests, documentation, and foundation-CI validation.
- Fresh incident candidates can become only `review_required`; mixed-resource input, authority contamination, and stale/future/non-candidate evidence fail closed or remain unknown.
- Real incident creation, containment, response execution, Protected/Covered status, deployment, and production acceptance remain separately governed.



Repository-native change history. Development source evidence does not establish deployment, Protected/Covered status, or production acceptance.

## 2026-09-28 — Detection Engine V1 development source

- Added a bounded Development correlation reference, schema, tests, documentation, and foundation-CI coverage.
- Runtime integration and production acceptance remain separate gates.

## 2026-09-28 — Repository-local project governance migration

- Added canonical `PROJECT-SPECIFICATIONS.md` and `PROJECT-RECORD.md` reconciled to protected main `2ddcf03b24b65e8e8112ba6cd18f9a9c56bb0a89`.
- Retired the competing root `SPECIFICATIONS.md` summary after incorporating its durable requirements.
- Updated README navigation and repository-governance validation so canonical project records are mandatory and both `SPECIFICATIONS.md` and retired `FEATURE-ROADMAP.md` fail closed if reintroduced.
- Reconciled project history to integrated PR #175 public-governance hardening, PR #174 fail-closed timestamp handling, and PR #179 repository-native feature tracking.
- Clarified that `PLANNED-FEATURES.md` is repository-native authority while the former Drive roadmap is migration provenance.
- The Drive project specification remains migration provenance until post-merge readback and governed source-retirement checks are complete; no production, Protected/Covered, release, or lifecycle promotion is implied.

## 2026-09-27 — Drive feature-roadmap migration

- Replaced the shorter repository roadmap with the materially richer current Drive planning source in `PLANNED-FEATURES.md`.
- Established `IMPLEMENTED-FEATURES.md` from the repository's explicit Foundation 0.9 source-state claims without promoting production/runtime acceptance.
- Preserved the raw Drive planning source under `docs/history/drive-feature-roadmap-source-2026-09-27.md`.
- Retired `FEATURE-ROADMAP.md` as a repository control.
- No production, Covered, Protected, release, or Stable promotion is implied.

## 2026-09-25 — Security timestamp failure containment

- Translate UTC conversion overflow into fail-closed validation across policy decisions, runtime execution authorization, durable execution/reconciliation, Identity/key lifecycle, Trust posture, Audit, Incident, Mesh evidence/runtime/refresh handling, persistence, platform-adoption governance, Protect, Quarantine, Security Center, service identity/key validity, and Scan replay.
- Remove platform-dependent epoch conversion from Identity/key lifecycle and Scan replay time calculations where relative UTC arithmetic is sufficient, keeping unsupported timestamp ranges controlled and non-authorizing.
- Require deployable Cloudflare authorization-issuer, quarantine-executor, and persistence claim timestamps to be non-empty, trimmed, timezone-qualified strings before Date parsing, preventing JavaScript coercion or timezone-less input from becoming authority-bearing time.
- Add a repository-wide timestamp-boundary regression sweep to exact-head foundation CI, retain focused per-module regression coverage, and pin the Cloudflare timezone-qualified timestamp requirement in static validators.
- Preserve execution_authority=false and all production/runtime acceptance boundaries. Independent security review and repository protection remain required before integration.

## Preserved historical changelog

The full legacy CHANGELOG.md content is preserved below. That legacy file remains temporarily for existing baseline tooling and references; wider feature/changelog migration is still pending and is not claimed complete by this fix. New entries belong in CHANGELOGS.md.

# Changelog

All notable source-controlled changes to the Wardveil Security foundation are recorded here.

## 0.9.0 — 2026-08-27

### Added

- Added `RUNTIME-AUTHORIZATION.md` and `contracts/wardveil.runtime-authorization.json` as the canonical cross-service execution-authorization contract between Wardveil Policy and Wardveil Protect.
- Added `reference/wardveil_runtime_authorization.py` with exact policy-digest, action, scope, executor, correlation, expiry, nonce, and idempotency binding.
- Added constant-time HMAC verification in the dependency-free reference path, explicitly labeled `HMAC-SHA256-reference-only` so source conformance cannot be mistaken for production key-management acceptance.
- Added replay-ledger semantics that permit only exact idempotent retries and reject conflicting nonce reuse.
- Added `AuthorizedProtectEngine` so a valid execution authorization is checked before the existing Protect executor receives a cross-service request.
- Added focused runtime-authorization tests and a contract validator, with exact-revision CI coverage.
- Added `EXECUTION-STATE.md`, `contracts/wardveil.execution-state.json`, and `reference/wardveil_execution_state.py` for durable authorization claims, executor/idempotency uniqueness, uncertain-outcome reconciliation, and execution receipts.
- Added `DurableAuthorizedProtectCoordinator`, which demonstrates verify -> durable claim -> Protect execution -> durable receipt sequencing without treating a pending claim as unused authorization.
- Added 14 focused execution-state tests plus a fail-closed contract validator.
- Extended the Cloudflare Durable Object persistence source with internal RPC-only execution-authorization claims, finalized execution receipts, bounded retention, receipt integrity digests, and an explicit `execution_reconciliation_required` state.
- Added CI TypeScript checking for the Cloudflare persistence adapter using exact TypeScript and Workers type-package versions in an isolated temporary dependency directory.
- Added `SERVICE-IDENTITY.md`, `contracts/wardveil.service-identity.json`, and `reference/wardveil_service_identity.py` for explicit first-party issuer/executor identities, capability bindings, and signing-key lifecycle.
- Added signed `signing_key_id` binding to Foundation 0.9 execution authorizations so verification can select the intended current key without exposing key material.
- Added active, suspended, and revoked service-identity states plus active, retired, and revoked signing-key states with bounded rotation overlap and immediate revocation semantics.
- Added focused service-identity/key-lifecycle tests covering rotation, retirement, revocation, unknown keys, algorithm mismatch, capability denial, identity suspension/revocation, and key/authorization expiry precedence.
- Added a separate `cloudflare/authorization-issuer/` Worker source candidate with a required encrypted signing-secret binding, fixed issuer/executor/key identities, exact policy/digest/scope/action/TTL revalidation, Worker-RPC signing, and health-only public HTTP.
- Added exact-revision CI validation and TypeScript compilation for both Cloudflare Wardveil Workers.
- Added `QUARANTINE-EXECUTOR.md`, `contracts/wardveil.quarantine-executor.json`, and `reference/wardveil_quarantine_executor.py` for the first bounded high-impact Wardveil Protect executor dedicated to `quarantine`.
- Added exact target-state readback, target-side idempotency, durable pre-side-effect claim handling, fail-closed uncertain-outcome reconciliation, non-destructive pending quarantine records, and nonsecret authorization provenance for Audit and Security Center.
- Added `cloudflare/quarantine-executor/` as a non-public Worker source candidate with persistence and target service bindings, a checked-in `REPLACE_AT_DEPLOYMENT` target placeholder, and explicit `unaccepted` runtime status.
- Added focused quarantine executor tests covering successful execution, target timeout/readback failure, identity/key denial, exact idempotent replay, and receipt-persistence failure after a possible side effect.
- Added `.github/workflows/deploy-cloudflare-quarantine-executor.yml` and `contracts/wardveil.quarantine-executor-deployment.json` as the exact-revision, manual, least-privilege Cloudflare deployment gate for the quarantine executor.
- Added `cloudflare/quarantine-executor-acceptance-runner/`, a local-only remote-service-binding probe that verifies deployed executor reachability and runtime placeholder replacement without creating a valid policy/authorization or authorizing a quarantine side effect.
- Added deployment validation that requires a pre-existing target Worker and persistence Worker, an explicit resource-type subset, a pre-provisioned encrypted verification secret, disabled Workers.dev/preview URLs, ephemeral generated configuration, revision-bound evidence, and continued `unaccepted` runtime status.

### Changed

- Advanced the Wardveil Security foundation to 0.9.0.
- Strengthened the capability contract so high-impact cross-service Protect execution requires bound runtime authorization and a Wardveil Policy decision is explicitly not execution authority by itself.
- Strengthened architecture, compatibility, integration, threat-model, and adoption guidance around executor identity, target authority, replay resistance, idempotency, expiry, and production key-management boundaries.
- Extended machine-readable identity metadata with the runtime-authorization contract and an explicit `unaccepted` production-runtime status.
- Strengthened the Foundation 0.9 runtime flow so a durable claim precedes an external high-impact side effect and a durable authoritative Protect receipt follows it.
- Extended the existing Cloudflare persistence boundary without adding a public mutation API; execution-state operations remain service-binding/RPC-only.
- Strengthened runtime authorization so signing-key identity is part of the signed authorization material and unknown, revoked, issuer-mismatched, or algorithm-mismatched keys fail closed in the identity-aware path.
- Separated the Cloudflare authorization-issuer source candidate from the persistence Durable Object so persistence does not become a key-management or signing authority.
- Extended compatibility metadata to treat service identity/key lifecycle as a separately versioned interoperability domain.
- Extended Wardveil Protect from a generic high-impact execution reference to a concrete quarantine-only source path while preserving the target system as resource authority and Quarantine as distinct from deletion.
- Extended Cloudflare deployment discipline so a production-candidate quarantine executor dispatch cannot silently inherit the broad source resource list or the source target placeholder; both target identity and the authorized resource-type subset must be supplied and validated at dispatch.
- Extended exact-revision CI to validate the quarantine execution contract, the Cloudflare deployment gate, the local-only remote-binding acceptance runner, and all associated TypeScript source.

### Security invariants

- High-impact cross-service actions fail closed when authorization is absent, expired, future-dated beyond the accepted skew, tampered, bound to a different policy/action/scope/executor, or reused with conflicting replay identity.
- Authorization cannot outlive the authoritative policy decision that produced it.
- A valid Wardveil authorization does not transfer underlying resource authority and cannot compensate for an executor that lacks action or resource permission.
- Signing secrets are prohibited from authorization envelopes, durable execution-state records, shared security records, source-controlled configuration, and CI logs.
- Reusing one executor/idempotency identity under a different durable claim fails closed.
- A durable claim without a finalized receipt is `execution_reconciliation_required`; Wardveil prohibits automatic blind re-execution because the external side effect may already have occurred.
- A finalized exact retry returns the original receipt without invoking the reference handler again.
- Durable Wardveil replay state does not make a non-idempotent external system exactly-once; production executors require target-system idempotency or authoritative reconciliation.
- Active issuer and executor service identities require their explicit Wardveil capabilities; suspended, revoked, expired, unknown, or capability-mismatched identities fail closed.
- Retired signing keys cannot create new authorizations, may verify only during a bounded overlap, and become unusable immediately if revoked.
- `signing_key_id` is nonsecret provenance metadata; the corresponding key material remains separate and must never be copied into Wardveil Audit or Security Center evidence.
- The Cloudflare authorization-issuer candidate exposes no public signing route. Signing is designed for authenticated internal Worker RPC/service-binding use, while `/healthz` remains the only public HTTP function.
- A quarantine target call is not a successful quarantine result without exact authoritative target-state readback bound to the same operation identity.
- Quarantine remains non-destructive pending review. Release and removal require separate explicit authority, and a quarantine transport binding does not become resource authority.
- Target timeout, ambiguous outcome, failed readback, or post-side-effect receipt persistence loss remains reconciliation-required and never authorizes blind re-execution.
- The tracked Cloudflare quarantine executor configuration retains `REPLACE_AT_DEPLOYMENT`; a deployment target is selected only through the controlled deployment gate and is not silently committed as production truth.
- A quarantine deployment must explicitly narrow the resource-type allow-list. The source list is not implicit production authorization.
- The verification secret must be pre-provisioned as an encrypted Worker secret; the deployment workflow reads only secret names and does not bootstrap, print, or persist secret material.
- The deployment acceptance runner is deliberately non-mutating. A passing internal service-binding probe does not establish target idempotency/readback behavior or successful quarantine enforcement.
- The in-memory HMAC, service-identity/keyring, execution-state, and quarantine-executor references are conformance mechanisms only. Cloudflare Worker source and deployment workflows are deployable source only. Production runtime acceptance still requires approved cryptography/key management, authenticated production service identities and transport, deployed durable state, authorized target-side quarantine integration, controlled real mutation/readback evidence, Audit/Security Center integration, reconciliation procedures, rotation/revocation evidence, Privacy Shield acceptance, applicable Everkeep evidence, and runtime failure/recovery exercises.
- `Protected by Wardveil` remains evidence-scoped and is not authorized by the existence of a runtime-authorization envelope, service identity, signing key, durable execution-state claim, quarantine-executor deployment, or non-mutating transport probe alone.

## 0.8.0 — 2026-08-26

### Added

- Added `ARCHITECTURE.md` as the canonical first-party security architecture for Wardveil Trust, Protect, Detect, Scan, Policy, Quarantine, Audit, Response, and Security Center.
- Added `contracts/wardveil.capabilities.json` with machine-readable capability responsibilities, authority declarations, lifecycle ordering, and cross-cutting security invariants.
- Added `scripts/validate_wardveil_capabilities.py` and exact-revision CI enforcement for the canonical capability contract.
- Added explicit Everkeep and GoreeCloud Mesh relationship metadata to the Wardveil identity contract.

### Changed

- Advanced the Wardveil Security foundation to 0.8.0.
- Advanced Wardveil from a primarily status/presentation description to a scoped first-party security system and shared security plane while preserving external producer authority boundaries.
- Approved Wardveil Security Center as a substantive first-party capability rather than a reserved concept.
- Reworked the README around the first-party security lifecycle, technical authority boundaries, fail-closed mutation, least privilege, auditability, and application integration.
- Updated the main foundation validator to require the new architecture, capability contract, platform relationships, and synchronized 0.8 metadata.

### Security invariants

- Evidence remains mandatory before reassurance or a `Protected by Wardveil` claim.
- Missing, stale, unsupported, malformed, or unverified required evidence continues to fail closed.
- Wardveil-native technical authority is explicitly scoped; unrelated producers retain authority over their own underlying technical state until integrated through a Wardveil contract.
- High-impact security mutation requires explicit executor authority and audit evidence.
- Unknown scan results are not interpreted as clean, and anomaly detection alone is not treated as proof of malicious activity.
- Privacy Shield remains a separate privacy authority; Everkeep remains the resilience/recovery authority; GoreeCloud Mesh remains the coordination/governance plane; Glaze UI remains the presentation and interaction system.

## 0.7.0 — 2026-08-20

### Added

- Promoted the Privacy Shield read-only status-presentation boundary into explicit foundation metadata with a versioned interoperability contract.
- Added machine-readable Privacy Shield presentation compatibility metadata, including read-only behavior, privacy-authority separation, raw-private-activity prohibition, and exclusion from the primary required-control aggregation by default.
- Added release-discipline guidance requiring foundation version, identity metadata, compatibility metadata, changelog state, and validator expectations to remain synchronized.

### Changed

- Advanced the foundation version to 0.7.0.
- Updated the canonical relationship metadata from the older Browser-specific Privacy Shield label to the platform-wide `GoreeCloud Privacy Shield` identity.
- Updated the repository status to reflect the approved canonical icon, implemented public Wardveil site, and versioned Privacy Shield interoperability contract.
- Clarified that Wardveil 0.7 remains read-only by default and that application-owned remediation remains outside the shared foundation.

### Security and authority boundaries

- Privacy Shield remains the authoritative privacy capability and runtime owner; Wardveil is only a privacy-safe read-only presenter of its status.
- Privacy Shield status remains excluded from Wardveil's primary required-control protection aggregation by default.
- A Privacy Shield `protected` record does not authorize `Protected by Wardveil` by itself.
- Missing, malformed, unsafe, stale, unsupported, or ambiguous Privacy Shield evidence fails closed to an unknown/unavailable presentation.
- Wardveil foundation acceptance remains separate from product-specific runtime acceptance and production approval.

## 0.6.0 — 2026-08-18

### Fixed

- Corrected stale machine-readable identity metadata that still reported `foundation_version: 0.3.0` after the repository had advanced to 0.5.0.
- Added fail-closed validator checks requiring `contracts/wardveil.identity.json` to match the authoritative `VERSION` file.

### Added

- Added `COMPATIBILITY.md` to define separate foundation and interoperability-contract version domains.
- Added machine-readable aggregation and compatibility metadata to `contracts/wardveil.identity.json`.
- Added validator enforcement for status-contract and aggregation-contract version consistency.
- Added explicit unsupported-future-version guidance for Wardveil consumers.

### Changed

- Advanced the foundation version to 0.6.0.
- Made version drift a validation failure instead of permitting parseable-but-stale metadata.

### Unchanged gates

- Wardveil remains read-only by default and does not define a generic remediation or execute API.
- Underlying authoritative producers remain responsible for technical security state.
- The canonical Wardveil icon remains unapproved and the visual-showcase gate remains blocked pending issue #2.

## 0.5.0 — 2026-08-18

### Added

- Added `AGGREGATION.md` with deterministic, conservative multi-source presentation semantics.
- Added `contracts/wardveil.aggregation.vectors.json` with protected, unknown, attention, degraded, not-applicable, empty-input, and invalid-input conformance cases.
- Added `scripts/validate_wardveil_aggregation.py`, a zero-dependency reference implementation and conformance validator.
- Added exact-head CI coverage for aggregation conformance.

### Changed

- Advanced the foundation version to 0.5.0.
- Made the 0.4 conservative aggregation rule deterministic with explicit precedence: degraded, attention, unknown, protected, then not applicable.
- Required empty required sets and malformed states to fail closed rather than produce a protected summary.
- Required aggregate protection claims to remain false unless every required applicable record is protected.

### Unchanged gates

- Wardveil remains read-only by default and does not define a generic remediation or execute API.
- Underlying authoritative producers remain responsible for technical security state.
- No canonical Wardveil icon artwork has been generated or approved.
- Wardveil remains blocked from visual showcase until issue #2 is completed and the approved SVG is stored at `branding/wardveil-security-icon.svg`.

## 0.4.0 — 2026-08-18

### Added

- Added `THREAT-MODEL.md` with explicit authoritative-producer, adapter, consumer, and operator trust boundaries.
- Added controls for false protection claims, provenance loss, scope confusion, sensitive-data leakage, stale-state replay, parser abuse, UI deception, privilege expansion, and supply-chain compromise.
- Added a conservative aggregation rule: a Wardveil summary cannot be more favorable than the weakest required evidence for the represented scope.
- Added `ADOPTION.md` with mandatory integration, privacy, accessibility, stale-evidence, rollback, testing, and exact-revision acceptance requirements.
- Added an explicit remediation boundary: Wardveil 0.4 remains read-only/status-focused and does not create a generic cross-platform command channel.

### Changed

- Advanced the foundation version to 0.4.0.
- Reworked the README around Wardveil's security architecture, trust boundaries, shared contracts, conservative aggregation, read-only default, and evidence-based adoption requirements.
- Clarified that branding alone is never sufficient to claim Wardveil integration or protection.

### Unchanged gates

- No canonical Wardveil icon artwork has been generated or approved.
- Wardveil remains blocked from visual showcase until issue #2 is completed and the approved SVG is stored at `branding/wardveil-security-icon.svg`.
- Technical SVG validation does not replace explicit aesthetic identity approval, small-size review, monochrome review, Glaze UI light/dark review, or identity-distinction review.

## 0.3.0 — 2026-08-18

### Changed

- Recorded Wardveil Security as an original GoreeCloud identity in the canonical repository documentation and machine-readable identity contract.
- Recorded that no conflicting Wardveil Security identity is identified in the current GoreeCloud project records.
- Removed external name-conflict and legal-clearance review as a current GoreeCloud use, release, integration, or visual-showcase gate.
- Reframed formal trademark or name-clearance review as optional future due diligence for expanded commercial, registration, package, app-store, or other public-use contexts.
- Kept the legal wording narrow: the GoreeCloud project record does not itself constitute trademark registration or a legal guarantee of exclusivity in every jurisdiction.

### Unchanged gates

- Canonical Wardveil icon artwork remains pending.
- The technical-authority, evidence-scoped protection-claim, privacy, least-privilege, and secret-exclusion boundaries remain unchanged.

## 0.2.0 — 2026-08-18

### Added

- `STATUS.md` interoperable Wardveil security-status semantics.
- `contracts/wardveil.status.schema.json` with fail-closed protected-state and protection-claim constraints.
- Non-sensitive protected and unknown-state examples.
- Repository security and secret-exclusion controls.

## 0.1.0 — 2026-08-18

### Added

- Initial Wardveil Security identity, integration, conformance, icon, validation, and machine-readable identity foundation.
