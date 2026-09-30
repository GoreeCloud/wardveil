# Wardveil Protect Reference Executor

Wardveil Protect is the controlled execution boundary between a valid Wardveil Policy decision and the system that can actually perform a protection action. The dependency-free reference implementation in `reference/wardveil_protect.py` demonstrates executor authorization, target binding, validity enforcement, replay resistance, explicit result state, and runtime-record emission without embedding any production-specific security mutation.

## Execution chain

`Trust -> Policy -> Protect authorization -> Explicit executor -> Protection result -> Audit`

A policy decision is not proof that an action executed. Wardveil Protect must validate the policy record, bind the decision to its represented scope, verify that the decision is still valid, confirm that the selected executor is authorized for the requested action and resource class, and then record the result.

## Executor authority

`ExecutorAuthority` declares an executor identity, the Wardveil actions it may perform, and optionally the resource types it may affect. High-impact actions such as restrict, quarantine, revoke, block, isolate, and escalate require both explicit executor authority and an execution handler. Missing authority or a missing handler fails closed.

The reference module performs no external security mutation by itself. A production integration must provide an application- or infrastructure-specific executor whose authority is independently established.

## Replay resistance

Every execution uses an idempotency key. Once a key has produced a result, replaying the same key returns the original result rather than invoking the executor again. Product integrations must persist replay state at an appropriate durability level for their threat model; the in-memory reference store demonstrates semantics only.

## Validity and scope

Expired, missing, malformed, unsupported, non-authoritative, or incorrectly scoped policy decisions are rejected. Wardveil Protect does not extend a policy decision's `valid_until` deadline and does not manufacture missing target scope.

## Result states

The reference executor emits `succeeded`, `failed`, or `rejected` protection-action results. A successful policy decision therefore remains distinguishable from successful enforcement. Security Center or other consumers must not infer execution success from Policy state alone.

## Non-mutating actions

`allow`, `allow_and_log`, `warn`, and `step_up` may be represented without an external mutation handler in the reference engine. High-impact actions require an explicit handler. Product-specific integrations may impose stricter requirements.

## Runtime records

`ProtectionResult.as_runtime_record()` emits the canonical `protection_action` record defined by `contracts/wardveil.runtime.schema.json`, including represented scope, policy action, executor identity, idempotency key, validity deadline, evidence references, and execution status.

## Acceptance boundary

This reference implementation proves deterministic contract behavior and supplies a reusable starting point. It does not prove that a production firewall, authentication system, application, service, quarantine engine, account-control system, or infrastructure executor has accepted or executed Wardveil actions. Product-specific runtime acceptance remains evidence-backed and separate.
