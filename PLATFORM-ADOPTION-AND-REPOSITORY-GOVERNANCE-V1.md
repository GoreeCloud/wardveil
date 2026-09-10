# Wardveil — Platform Adoption and Repository Governance v1

**Status:** Development candidate  
**Work package:** H — Platform Adoption and Repository Governance

## Purpose

This package defines how Wardveil records application/service adoption and repository-governance evidence without manufacturing stronger claims than the authoritative systems support.

Wardveil must never claim more protection than GoreeCloud can prove.

## Adoption lifecycle

The only Wardveil adoption progression is:

`Planned → Implemented → Source Validated → Runtime Validated → Production Accepted`

A later state requires evidence for every earlier state. Branding, documentation, a passing source test, repository membership, or a declared Platform Contract result cannot independently advance a consumer to Runtime Validated or Production Accepted.

Each adoption record must identify the consumer, exact Wardveil contract version, applicable capabilities, implemented capabilities, source revision, source-validation evidence, runtime-validation evidence, production-acceptance evidence, observation time, evidence freshness, gaps, remediation, and Stable-qualification impact.

Unknown, stale, contradictory, or unavailable required evidence fails closed and must remain visible.

## Repository governance evidence

Repository governance is a separate evidence domain from source correctness. A source revision may be source-valid while repository hosting controls remain unverified.

For Wardveil repository governance, evidence should cover the authoritative repository, hosting platform, default branch, exact observed revision/settings observation, pull-request enforcement, required checks, current-head or stale-review protection, force-push restrictions, branch-deletion restrictions, administrator-bypass restrictions, CODEOWNERS applicability/presence, CI status, and observation freshness.

Source-controlled files can prove source declarations and CODEOWNERS content. They cannot by themselves prove live GitHub branch protection or ruleset enforcement.

The current connector cannot read the authoritative GitHub `main` branch-protection endpoint; the request returns HTTP 403. Therefore Work Package H must represent current live branch-protection/ruleset enforcement as **unverified**, not protected or passing, until authoritative hosting-platform evidence is available.

Historical repository documentation records that `main` was unprotected on August 20, 2026. That historical fact must not be silently promoted to a current observation either. Current state remains unverified until re-observed authoritatively.

## CODEOWNERS

`.github/CODEOWNERS` exists and routes repository ownership to `@GoreeCloud`, including security-sensitive paths. CODEOWNERS presence is source evidence only; required-review enforcement still depends on live repository settings.

## Platform-system adoption

Every GoreeCloud application and service must be evaluated against all seven Integral Platform Systems. Wardveil adoption must therefore record substantive implementation status rather than badge or branding presence. Genuine non-applicability may be recorded only when explicitly justified.

Wardveil-facing adoption evidence must preserve the underlying authority of GoreeCloud Identity, Privacy Shield, Everkeep, GoreeCloud Mesh, GoreeCloud Manager, and Glaze UI. No adoption state transfers another system's authority to Wardveil.

## Acceptance boundary

This package may reach Source Validated with source-controlled contracts, tests, validators, and exact-head CI evidence even while live repository-governance settings are unverified. It must not claim the repository itself is fully governed until authoritative live hosting-platform evidence verifies all required controls.

Production consumers likewise remain below Production Accepted unless their exact runtime and production paths are independently verified.
