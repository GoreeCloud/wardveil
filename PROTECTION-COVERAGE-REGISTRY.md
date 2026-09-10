# Wardveil Protection Coverage Registry

## Status

**Development / source-reference candidate.**

This document describes the Work Package B source implementation for the Wardveil next upgrade. It does not establish runtime validation, production acceptance, Stable qualification, or any broad `Protected by Wardveil` claim.

## Purpose

The Protection Coverage Registry makes Wardveil coverage explicit per application, service, resource scope, and capability. It is separate from current threat state and separate from security-state claims.

The registry exists to answer questions such as:

- Is the applicable Wardveil capability actually integrated for this application or service?
- Which enforcement points are required and which are implemented?
- Is the supporting evidence current, stale, unavailable, or unverified?
- Has the integration reached source validation, runtime validation, or production acceptance?
- Which known gaps remain?
- Does the current coverage block Stable qualification?

Missing or stale coverage must remain visible. The registry must never turn the absence of a detected threat into evidence that protection exists.

## Coverage states

The next-upgrade coverage vocabulary is:

- `covered` — the accepted capability and required enforcement path are present with current evidence.
- `partial` — some required enforcement, scope, path, or acceptance requirement is incomplete.
- `not_covered` — the capability is absent, intentionally unavailable, or still only planned for the scope.
- `unknown` — Wardveil cannot determine current coverage from valid evidence.
- `stale` — previously established coverage evidence is no longer fresh enough for the current claim.
- `degraded` — coverage exists but a required supporting control or dependency is impaired.

Coverage remains independent from security state. A subject can have no current malicious finding while its malware protection coverage is `unknown`, `stale`, `partial`, or `not_covered`.

## Adoption lifecycle

Each coverage record also preserves the independent Wardveil adoption lifecycle:

`planned -> implemented -> source_validated -> runtime_validated -> production_accepted`

A source-valid or runtime-valid integration does not become fully `covered` for protection-claim purposes until the applicable capability is production accepted and its evidence remains current.

## Registry identity and scope

The registry key binds:

- subject kind (`application` or `service`)
- subject identifier
- resource scope kind
- resource scope identifier
- Wardveil capability

This prevents one application, service, environment, or capability from inheriting another scope's coverage state.

## Enforcement coverage

A coverage record may declare required and implemented enforcement points. A record that otherwise claims `covered` is downgraded to `partial` when any required enforcement point is absent.

This allows Security Center and acceptance tooling to distinguish a complete control path from a partially integrated one.

## Freshness and conflict behavior

Registry updates are ordered by authoritative observation time.

- Older evidence cannot overwrite a newer record for the same subject, scope, and capability.
- Conflicting evidence at the same observation time is rejected rather than resolved arbitrarily.
- Future-dated evidence is treated as unverified.
- Expired evidence becomes `stale`.
- Unavailable or unverified evidence becomes `unknown`.

These rules are intentionally fail closed.

## Stable qualification impact

The source reference exposes three bounded impact values:

- `none` — current `covered` capability at `production_accepted`.
- `blocks_stable` — known partial, not-covered, stale, or degraded coverage blocks Stable qualification for a required capability.
- `unknown` — current coverage cannot be established from valid evidence.

This is a coverage input to Stable qualification, not a complete Stable decision by itself.

## Source files

- `reference/wardveil_protection_coverage_registry.py`
- `contracts/wardveil.protection-coverage.v1.schema.json`
- `reference/wardveil_security_state_v2.py`
- `contracts/wardveil.security-state.v2.schema.json`
- `scripts/test_wardveil_protection_coverage_registry.py`
- `scripts/test_wardveil_security_state_v2.py`
- `scripts/validate_wardveil_security_state_v2.py`
- `.github/workflows/validate-next-upgrade-security-state.yml`

## Validation boundary

The source tests verify registry identity isolation, enforcement-point downgrades, adoption-state handling, stale evidence, degraded coverage, unavailable evidence, aggregate coverage, missing capabilities, out-of-order update rejection, same-time conflict rejection, application/service separation, and contract export.

These tests establish only source-level behavior. Runtime observation, live application integration, Security Center consumption, deployment, production acceptance, and Stable qualification remain separate evidence gates.
