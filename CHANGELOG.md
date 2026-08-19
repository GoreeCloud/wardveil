# Changelog

All notable source-controlled changes to the Wardveil Security foundation are recorded here.

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
