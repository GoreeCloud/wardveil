# Wardveil Security Status Contract

## Purpose

This contract defines the minimum interoperable security-status record that GoreeCloud applications and services may expose to a Wardveil-facing presentation layer.

It deliberately separates **presentation** from **technical authority**. Wardveil does not create, infer, or certify the underlying security state. An authoritative application, service, policy engine, monitor, or control produces the evidence; a Wardveil integration may normalize that evidence for consistent presentation.

## Required semantics

Every status record must identify:

- the scope being evaluated;
- the authoritative source and control that produced the state;
- the normalized Wardveil presentation state;
- when the evidence was observed;
- whether the evidence is current enough for the intended decision;
- whether a `Protected by Wardveil` claim is permitted for that record;
- any privacy-conscious redactions or withheld details needed to preserve least privilege.

Missing evidence is not passing evidence. A producer must use `unknown` when required evidence is missing, stale, unavailable, or cannot be verified.

## Normalized states

The allowed presentation states are:

- `protected` — current authoritative evidence supports the defined protection scope;
- `attention` — review or user action is recommended;
- `degraded` — a protection path or evidence path is below its intended state;
- `unknown` — required evidence is unavailable, stale, incomplete, or unverified;
- `not_applicable` — the control does not apply to the current scope.

These are Wardveil presentation semantics only. They do not replace the source system's own state machine.

## Protection-claim rule

`claim.protected_by_wardveil` may be `true` only when all of the following are true:

1. `state` is `protected`;
2. `authority.authoritative` is `true`;
3. `evidence.status` is `current`;
4. the record has a non-empty authoritative source and control identifier;
5. the claim applies only to the explicit scope represented by the record.

If any condition is not satisfied, the value must be `false`.

## Evidence freshness

`evidence.observed_at` must identify when the underlying source last evaluated the state. A producer may additionally provide `evidence.valid_until` when it has a defined freshness window.

If evidence has exceeded its source-defined freshness window, the producer must not preserve a `protected` presentation solely because the last known result passed. The producer should emit `unknown` or another source-appropriate non-passing state.

## Privacy and sensitive-information boundary

Wardveil status records must be data-minimized. They must not contain reusable secrets or authentication material, including passwords, private keys, API tokens, setup keys, session tokens, recovery codes, multifactor seeds, or secret environment values.

Records should also avoid raw request or response bodies, cookies, unnecessary personal information, detailed internal topology, unrestricted logs, and raw exception content. A producer may include a short sanitized summary and non-secret reference suitable for an authorized user to locate more detail in the authoritative system.

`privacy.redactions` may describe categories intentionally withheld. It must not reproduce the withheld values.

## Machine-readable contract

The interoperable JSON structure is defined by:

- `contracts/wardveil.status.schema.json` — schema, allowed values, and machine-enforced fail-closed constraints;
- `examples/wardveil.status.example.json` — non-sensitive protected-state example backed by current authoritative evidence;
- `examples/wardveil.status.unknown.example.json` — non-sensitive fail-closed example showing stale evidence mapped to `unknown` with the Wardveil protection claim disabled.

The repository validator checks both examples, the canonical state vocabulary, protected-state invariants, protection-claim invariants, privacy metadata, and common secret-bearing material using only the Python standard library.

## Visual identity boundary

This status contract may be implemented before Wardveil's canonical icon is approved. Until the canonical icon gate in `ICON.md` passes, applications may use text-based Wardveil integration but must not present temporary artwork as the official Wardveil identity.
