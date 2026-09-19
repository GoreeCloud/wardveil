# Wardveil Security — Repository Notes

## Current lifecycle

Wardveil Security is in **Development**. Foundation 0.9 and next-upgrade source contracts/reference models are substantial, but overall production protection, release, Protected/Covered status, and Stable qualification remain independently gated.

Do not use a single global “protected” state to summarize all Wardveil consumers or capabilities.

## Current authoritative source state

As of the September 19, 2026 stabilization line, authoritative `main` is based on the current Foundation 0.9 source plus the next-upgrade security-state work and the Glaze UI authority/lifecycle reconciliation.

Current repository configuration uses Platform Contract 0.4, evaluates exactly nine Integral Platform Systems, keeps GoreeCloud Sync separately governed, and requires Glaze UI 1.6.0 as the current shared consumer target.

Security Center source/build migration to Glaze UI 1.6.0 is integrated through PR #150. Human rendered review, representative accessibility/performance, rollback, deployed-byte/provenance, consumer-registry, deployment, runtime, and production acceptance remain open.

## Current runtime boundary

Wardveil has validated Development/source contracts and selected bounded runtime evidence, including the Wardveil Scan line. This does not establish platform-wide production acceptance.

Open production boundaries include production Identity/key custody and approved cryptography, live target execution/readback, Privacy Shield acceptance, Everkeep recovery acceptance, GoreeCloud Policy and Observability integration, remaining Security Center 1.6 rendered/runtime/deployment acceptance, deployment/rollback, monitoring, and Stable qualification.

## Documentation authority

- Canonical project specification: `Project Specification — Wardveil Security` in `GoreeCloud/Projects`.
- Canonical Wardveil policy: `Policy — Wardveil Security`.
- Repository specification: `SPECIFICATIONS.md`.
- Repository capability state: `CAPABILITIES.md`.
- Repository roadmap: `FEATURE-ROADMAP.md`, synchronized with the applicable GoreeCloud Feature Roadmap control.
- Repository user manual: `USER-MANUAL.md`, with the central User Manuals representation maintained separately.
- Branding authority: `GoreeCloud/goreecloud-branding-assets`; repository branding is a synchronized consumer derivative.

## Historical and draft work

Old branches, historical PRs, prior Foundation versions, old Security Center Glaze UI baselines, and draft identity concepts are provenance only unless explicitly reconciled to current authoritative source and accepted through the current governance path.

## Sensitive information

Do not commit credentials, bearer tokens, private keys, signing secrets, recovery codes, private user content, unrestricted operational evidence, or secret-bearing evidence locators.

Evidence committed to this repository must remain minimized, sanitized, and safe for the repository’s access boundary.

## Maintenance

Use this file for repository-level development and maintenance observations that do not belong in authoritative policy, project specifications, formal changelogs, or task management.

Promote stable decisions and requirements to the appropriate authoritative record instead of leaving them only in repository notes.
