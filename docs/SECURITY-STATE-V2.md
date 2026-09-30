# Wardveil Next-Upgrade Security-State Engine

## Status

**Development / source-reference candidate.**

This document describes the current source implementation of the next Wardveil upgrade security-state foundation and its Protection Coverage Registry. It does not establish runtime validation, production acceptance, Stable qualification, or a broad `Protected by Wardveil` claim.

## Purpose

The new state engine separates three concepts that the earlier presentation contract could not represent independently:

1. **Security state** — what Wardveil can currently prove about the scoped security condition.
2. **Protection coverage** — which security capabilities are actually integrated and accepted for that scope.
3. **Evidence validity** — whether the evidence supporting the state is authoritative, current, inside its validity window, and bound to the exact represented scope.

The defining rule remains:

> Wardveil must never claim more protection than GoreeCloud can prove.

## Next-upgrade security states

The source contract introduces:

- `protected`
- `at_risk`
- `action_required`
- `unknown`
- `not_covered`
- `degraded`
- `contained`
- `recovering`
- `reconciliation_required`

These states are deliberately more expressive than the Foundation 0.9 presentation vocabulary.

`protected` is permitted only when the required protection coverage is `covered`, required evidence is authoritative and current, at least one current authoritative record verifies protection for the exact represented scope, and no higher-priority adverse state is active.

`not_covered` means the capability applies to the scope but Wardveil does not have the required accepted integration. It is not equivalent to `not_applicable`.

`reconciliation_required` means a security-sensitive side effect may have occurred but Wardveil cannot yet prove the final target state. The original authorization must not be blindly replayed.

## Protection coverage

`contracts/wardveil.protection-coverage.v1.schema.json` defines per-capability coverage for authentication protection, authorization enforcement, session protection, device trust, malware protection, malicious URL protection, vulnerability monitoring, security-update posture, secret protection, network exposure controls, runtime integrity, security-event reporting, audit coverage, and recovery-security verification.

Coverage state is separate from implementation/adoption state.

Coverage uses:

- `covered`
- `partial`
- `not_covered`
- `unknown`
- `stale`
- `degraded`

`stale` preserves the distinction between previously established coverage whose evidence has expired and a capability that was never covered. `degraded` preserves the distinction between a present control path with impaired supporting controls and an absent integration.

Adoption uses `planned`, `implemented`, `source_validated`, `runtime_validated`, and `production_accepted`.

A capability is not treated as fully covered by the reference evaluator unless it has current evidence and reaches `production_accepted`.

## Protection Coverage Registry

`reference/wardveil_protection_coverage_registry.py` provides the first executable Work Package B registry reference.

The registry binds coverage to the exact application or service, exact resource scope, and exact Wardveil capability. It tracks required and implemented enforcement points, dependencies, known gaps, remediation, evidence freshness, and Stable-qualification impact.

Registry updates reject older evidence that would overwrite a newer observation and reject conflicting records at the same observation time. Missing enforcement points downgrade an otherwise covered capability to `partial`. Future-dated or unavailable evidence fails closed to `unknown`; expired evidence becomes `stale`.

See `PROTECTION-COVERAGE-REGISTRY.md` for the registry contract and source-validation boundary.

## Evidence rules

Evidence is evaluated fail closed. A current record must come from an authoritative producer, not be future-dated, include a bounded `valid_until`, remain inside that validity window, and preserve the exact scope represented by the assessment.

Each `EvidenceObservation` carries an explicit `scope_kind` and `scope_id`. The public evaluator also requires the exact scope being assessed. If any evidence record is bound to another otherwise-valid scope, the assessment fails closed to `unknown` with `required_evidence_scope_mismatch`; foreign-scope evidence cannot authorize a `protected` claim.

The exact scope also travels with the resulting `SecurityAssessment`. Serialization uses that assessment-bound scope. A caller may provide the same scope again as an assertion, but attempting to serialize the assessment under another scope is rejected. Presentation cannot relabel evidence-derived protection authority after evaluation.

Scope kinds follow the security-state contract vocabulary: `account`, `application`, `service`, `device`, `network`, `data`, `control`, `platform`, and `other`. Scope IDs are non-empty, canonical, bounded to the schema's 128-character ceiling, and control-free.

Missing evidence becomes `unknown`. Non-authoritative evidence becomes `unknown`. Expired evidence becomes `unknown` at the security-state layer while its protection coverage remains explicitly `stale`. Current health or source availability alone does not prove protection unless the evidence explicitly verifies the represented protection.

## Compatibility

Foundation 0.9 status records remain valid and unchanged.

The reference model supplies a conservative mapping for older Security Center consumers:

- `protected` -> `protected`
- `at_risk`, `action_required`, `contained` -> `attention`
- `degraded`, `recovering`, `reconciliation_required` -> `degraded`
- `unknown`, `not_covered` -> `unknown`

This mapping prevents old consumers from treating a more precise next-upgrade state as stronger than it is.

## Files

- `contracts/wardveil.security-state.v2.schema.json`
- `contracts/wardveil.protection-coverage.v1.schema.json`
- `reference/wardveil_security_state_v2.py`
- `reference/wardveil_protection_coverage_registry.py`
- `scripts/test_wardveil_security_state_v2.py`
- `scripts/test_wardveil_protection_coverage_registry.py`
- `scripts/validate_wardveil_security_state_v2.py`
- `PROTECTION-COVERAGE-REGISTRY.md`

## Validation

Run:

```bash
python3 scripts/test_wardveil_security_state_v2.py
python3 scripts/test_wardveil_protection_coverage_registry.py
python3 scripts/validate_wardveil_security_state_v2.py
python3 -m py_compile \
  reference/wardveil_security_state_v2.py \
  reference/wardveil_protection_coverage_registry.py \
  scripts/test_wardveil_security_state_v2.py \
  scripts/test_wardveil_protection_coverage_registry.py \
  scripts/validate_wardveil_security_state_v2.py
```

These checks establish only source-level behavior for this development candidate.
