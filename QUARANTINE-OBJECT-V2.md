# Wardveil Next-Upgrade Quarantine Object

## Status

**Development / source-reference candidate.**

This document describes the source-level Work Package C quarantine-object and reconciliation model for the Wardveil next upgrade. It does not establish live target execution, runtime validation, production acceptance, Stable qualification, or a broader `Protected by Wardveil` claim.

## Purpose

Wardveil Quarantine must be a durable, non-destructive security workflow rather than a boolean flag. A quarantine request is not proof that the target was isolated, and successful delivery of an execution request is not proof that the target reached the requested state.

The source contract therefore makes target-state verification and reconciliation explicit.

## Quarantine lifecycle

The baseline quarantine flow is:

`quarantine_pending -> isolation_requested -> isolation_executing -> verified_quarantined`

`verified_quarantined` is permitted only after authoritative target-state readback is available and bound to the action. The object retains the target authority, resource type and identifier, initiating finding, policy decision, execution authorization, executor, idempotency key, target-state reference, verified resulting state, evidence, incident linkage, and audit provenance.

A successful request, authorization, executor call, acknowledgement, or transport result alone cannot create `verified_quarantined`.

## Durable states

The source contract supports:

- `quarantine_pending`
- `isolation_requested`
- `isolation_executing`
- `verified_quarantined`
- `reconciliation_required`
- `release_pending`
- `released`
- `restore_pending`
- `restored`
- `rescan_pending`
- `escalated`
- `removal_pending`
- `removed`
- `failed`

These states preserve uncertainty and action progress rather than flattening the entire lifecycle into quarantined/not-quarantined.

## Separate authorization for follow-up actions

The quarantine object treats these as distinct security-sensitive actions:

- quarantine
- release
- restore
- remove
- rescan
- escalate
- recover

Each action requires its own authorization reference, executor binding, and idempotency key before it can enter the corresponding pending or action state.

`recover` is modeled as a separately authorized recovery/restoration transition; it does not inherit authorization from the original quarantine operation.

### Delete is intentionally separate

`delete` is deliberately rejected by the non-destructive quarantine-object reference with `destructive_delete_requires_separate_executor_contract`.

Delete is a destructive operation and must not be treated as ordinary quarantine removal. A future delete executor must have its own explicit authorization, target authority, irreversible-action safeguards, evidence, and acceptance requirements.

## Target-state verification

Completion of quarantine, release, restore, remove, rescan, or recover requires:

- an active separately authorized action;
- authoritative target-state reference;
- an explicit verified resulting state; and
- target-state verification evidence.

Without those inputs the source reference cannot transition to the requested completed state.

Rescan completion returns the object to `verified_quarantined`; a clean or completed rescan does not silently release content.

## Uncertain outcomes and reconciliation

When a security-sensitive side effect may have occurred but Wardveil cannot prove the final target state, the object transitions to `reconciliation_required`.

While reconciliation is required:

- no new security-sensitive action may begin;
- the original authorization is never reusable;
- Wardveil must query or otherwise verify the authoritative target state;
- Wardveil must not blindly replay the original operation.

The reference reconciliation outcomes are:

- `succeeded` — requires authoritative target-state proof before the corresponding completed state is recorded;
- `failed` — records failure without replay;
- `not_executed` — records failure and requires a fresh authorization before a later retry;
- `unknown` — keeps the object in `reconciliation_required`.

Resolving reconciliation never reopens the original authorization.

## Relationship to Foundation 0.9 execution safety

The next-upgrade object is additive to the existing Wardveil Foundation execution architecture. Existing source already separates policy decisions, signed execution authorization, durable pre-execution claims, target-side idempotency/readback, Protect receipts, Audit provenance, and execution reconciliation.

This Work Package C source adds the durable quarantine-domain lifecycle required by the next-upgrade project specification. It does not replace the existing high-impact executor or claim that a production Drive quarantine target has been accepted.

## Source files

- `contracts/wardveil.quarantine-object.v1.schema.json`
- `reference/wardveil_quarantine_object_v2.py`
- `scripts/test_wardveil_quarantine_object_v2.py`
- `scripts/validate_wardveil_quarantine_object_v2.py`
- `.github/workflows/validate-next-upgrade-security-state.yml`

Related existing Foundation source includes:

- `reference/wardveil_quarantine_executor.py`
- `reference/wardveil_execution_reconciliation.py`
- `reference/wardveil_execution_state.py`
- `scripts/test_wardveil_quarantine_executor.py`

## Validation boundary

The Work Package C self-tests verify:

- non-final request and execution states;
- target-state verification before successful quarantine;
- independent release authorization and verification;
- destructive Delete separation;
- reconciliation after uncertain outcomes;
- blocking of new actions while reconciliation is open;
- rejection of successful reconciliation without target-state proof;
- continued uncertainty when reconciliation remains unknown;
- fresh authorization after a proven not-executed action; and
- separately authorized rescan behavior without implicit release.

These checks establish source behavior only. Runtime target execution, deployment, production service identity and keys, live Drive target readback, durable production Audit evidence, Security Center consumption, Privacy Shield/Everkeep acceptance, and overall production acceptance remain separate gates.
