# Wardveil Policy Decision and Enforcement Contract v2

## Status

**Work Package:** I — Policy Decision and Enforcement Contract  
**Contract version:** 0.1.0  
**Lifecycle:** next-upgrade source-development candidate  
**Production acceptance:** not established

## Purpose

Wardveil Policy must produce a durable, explainable decision object instead of reducing security policy to a transient boolean. The decision must preserve enough bounded provenance to explain what was requested, which policy was evaluated, which identity and trust evidence applied, which result was reached, and what obligations remain.

A Wardveil Policy decision is not execution authorization.

A valid Policy record can establish that Wardveil Policy reached a bounded decision. It cannot by itself grant the target executor authority, prove that an external action executed, prove the target reached the requested state, or create a Protected state.

## Decision vocabulary

The v2 decision vocabulary is:

- `allow` — Policy permits the represented operation, subject to all independent authorization and target-authority requirements.
- `deny` — Policy does not permit the represented operation.
- `allow_with_obligations` — Policy permits the represented operation only when all declared obligations remain enforced.
- `require_step_up` — stronger or fresher evidence is required before Policy can permit the operation.
- `defer` — Wardveil cannot complete the decision at this layer because another required authority, specialized response path, or current evidence is required.
- `unknown` — Wardveil cannot establish a trustworthy decision from current valid evidence.

Unknown and Defer are not aliases for Allow.

Missing, malformed, stale, expired, revoked, unbound, or otherwise insufficient decision evidence fails closed.

## Durable decision binding

Every decision is bound to:

- a unique decision ID and correlation ID;
- policy identity, version, and digest;
- actor subject and/or service identity;
- exact requested action;
- exact target reference;
- explicit purpose;
- scopes and audiences;
- current trust state and trust evidence references;
- decision outcome;
- bounded reason codes;
- obligations;
- evidence references;
- observation and expiration times;
- revocation state; and
- the explicit execution-authority boundary.

A decision that cannot prove these bindings is not usable for enforcement.

## Obligations and step-up

`allow_with_obligations` requires at least one explicit obligation. Examples include audit-event creation, target-state readback, user warning, fresh evidence collection, or another bounded requirement defined by the governing policy.

Consumers must not remove or weaken Policy obligations. They may always apply stricter local authorization or reduce privilege.

`require_step_up` means the operation is not currently permitted by the Policy result. The caller must obtain the stronger evidence or authentication required by the applicable authority and request a new decision rather than treating step-up as an eventual Allow.

## Revocation and validity

Policy decisions are short-lived evidence. Consumers must enforce `valid_until` and must reject expired decisions. A revoked decision fails immediately even if its original validity window has not elapsed.

A policy decision should be re-evaluated when its governing policy changes materially, required trust evidence becomes stale or invalid, relevant identity or credential state changes, a material security event occurs, or another authoritative dependency invalidates the assumptions behind the decision.

## Enforcement boundary

The contract requires all three statements to remain true:

1. `execution_authorization_required = true`
2. `policy_decision_is_execution_authorization = false`
3. `policy_decision_proves_execution_success = false`

Before an external side effect, the authorized executor must independently verify the separate execution authorization, including issuer, signature, audience, scope, target, action, expiration, replay protection, policy binding, executor identity, and any required evidence freshness.

Target-side resource authority remains independent. The target must still determine that the authenticated executor is permitted to perform the requested mutation.

## Foundation 0.9 compatibility

The v2 source model provides a conservative Foundation 0.9 compatibility mapping so existing reference semantics cannot silently gain stronger authority:

- `allow` → `allow`
- `allow_and_log` → `allow_with_obligations` + `audit_event_required`
- `warn` → `allow_with_obligations` + `user_warning_required`
- `step_up` → `require_step_up`
- `restrict`, `block`, `revoke` → `deny`
- `quarantine`, `isolate`, `escalate` → `defer` + `route_to_authorized_response_path`
- unrecognized legacy decisions → `unknown`

The compatibility mapping never creates execution authority or proof of execution.

## Security Center

Security Center should translate a Policy decision into a bounded explanation showing the current decision, applicable policy, requested action and target, reason codes, current evidence, trust basis, obligations, validity, revocation state, and recommended next step.

The explanation must not expose bearer credentials, signing secrets, private keys, raw private content, unrestricted authentication material, or unrelated personal information.

Security Center must distinguish Policy permission from execution authorization and from verified execution outcome. A successful Policy evaluation alone must never be displayed as proof that protection occurred.

## Privacy and evidence minimization

Policy records should contain stable identifiers, digests, bounded reason codes, scopes, audiences, evidence references, timestamps, and other minimum metadata needed for authorization provenance and explanation. They should not duplicate private source content merely to make a decision explainable.

Privacy Shield retains privacy authority. Wardveil Policy may enforce a security requirement that depends on Privacy Shield evidence when an approved integration contract permits it, but Wardveil must not manufacture or override Privacy Shield consent, purpose, minimization, retention, or disclosure authority.

## Production acceptance boundary

This Work Package I milestone is source-level development only.

Source tests and contract validation can demonstrate deterministic Policy semantics and fail-closed compatibility behavior. They do not prove a deployed Policy service, production identity/key custody, runtime decision issuance, target-executor enforcement, execution authorization, replay/revocation behavior in production, Security Center live consumption, or production acceptance.

Production acceptance requires exact-environment evidence for the full applicable decision and enforcement path, including authoritative Identity evidence, current trust inputs, policy provenance, separate execution authorization, target-side authority verification, execution outcome verification, Audit provenance, and failure behavior.

This package does not authorize a broader `Protected by Wardveil` claim.
