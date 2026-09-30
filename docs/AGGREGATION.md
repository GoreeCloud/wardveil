# Wardveil Security Aggregation Contract

## Purpose

This contract defines deterministic presentation semantics for combining multiple Wardveil status records into one bounded summary without creating new technical authority.

Aggregation is a presentation operation. It does not certify controls, replace producer state, or authorize remediation.

## Required inputs

A summary may aggregate only records whose scopes are explicitly included in the requested summary. Consumers must not silently expand scope or combine unrelated records merely because they are available.

Every included record remains attributable to its authoritative producer and control. The aggregate must preserve enough provenance for an authorized user to identify which underlying record caused a non-passing summary.

## Deterministic precedence

For required records, Wardveil uses the following conservative presentation precedence from strongest blocker to least blocker:

1. `degraded`
2. `attention`
3. `unknown`
4. `protected`
5. `not_applicable`

The aggregate state is the highest-precedence state present among required applicable records.

`not_applicable` never masks an applicable record. If every included record is `not_applicable`, the aggregate is `not_applicable`.

A required `unknown` record always prevents a `protected` aggregate. Known `degraded` or `attention` evidence remains visible instead of being hidden by unrelated unknown evidence.

## Protection claim

An aggregate may set `Protected by Wardveil` only when every required applicable record is `protected`, every protected record is backed by current authoritative evidence, and no required record is `attention`, `degraded`, or `unknown`.

An all-`not_applicable` aggregate is not a protection claim.

## Empty and malformed inputs

A consumer must fail closed on an empty required set, malformed state values, missing required provenance, or inputs that cannot be verified against the Wardveil status contract. Such conditions must not produce `protected`.

## Scope and optional records

Products may define optional informational records, but optionality must be explicit before aggregation. A consumer must not downgrade a required record to optional merely to improve the summary.

Optional records may be presented separately. If a product chooses to include optional records in the primary summary, that behavior must be documented and must not make the summary more favorable than the required-record result.

## Privacy

Aggregation must not concatenate raw diagnostics, unrestricted logs, credentials, tokens, topology, or other sensitive detail. Summaries should carry only data-minimized reason identifiers or sanitized references needed to explain the resulting state.

## Reference implementation

`scripts/validate_wardveil_aggregation.py` provides the repository reference implementation and validates the conformance vectors in `contracts/wardveil.aggregation.vectors.json`.

The reference implementation exists to make presentation semantics deterministic. It is not a security decision engine and does not replace authoritative producer logic.

## Compatibility boundary

This contract supplements `STATUS.md`, `THREAT-MODEL.md`, and `ADOPTION.md`. Wardveil remains read-only by default, and this contract does not introduce a generic remediation or execute API.

The canonical icon showcase gate remains independent and unchanged.
