# Wardveil Runtime Security Contracts

This document defines the first implementation-facing contract layer for Wardveil Security 0.8. It translates the canonical architecture and feature specification into bounded records that GoreeCloud applications and services can implement without inventing incompatible security semantics.

These contracts do not by themselves prove runtime deployment, production acceptance, or Stable qualification. Each producer and executor remains responsible for its own actual control state and must provide current authoritative evidence.

## Common envelope

Every Wardveil runtime record must carry a contract version, record type, record identifier, correlation identifier when relevant, authoritative producer identity, represented scope, observation or decision time, validity boundary where required, and evidence references. Shared records must exclude reusable secrets, credentials, private keys, recovery material, raw private activity, and unnecessary personal data.

## Trust decision

Wardveil Trust evaluates an authenticated or otherwise identified actor in context. A trust decision records the principal class, target resource or service, authentication strength, device/session context, applicable signal references, resulting trust state, reason codes, recommended verification requirements, observation time, and validity boundary.

Canonical trust states are `trusted`, `normal`, `elevated_risk`, `restricted`, and `blocked`.

Trust is not authorization. A favorable trust state does not itself grant access; Wardveil Policy still evaluates the requested operation and applicable policy.

## Policy decision

Wardveil Policy records the actor, requested operation, target resource, policy-set identifier/version, trust input, applicable evidence references, decision, reason codes, validity window, and whether an enforcement action is required.

Canonical decisions are `allow`, `allow_and_log`, `warn`, `step_up`, `restrict`, `quarantine`, `revoke`, `block`, `isolate`, and `escalate`.

A policy decision must be scoped to the intended actor, resource, operation, and validity window. High-impact decisions must not be replayable against a different target or privilege context.

## Detection finding

Wardveil Detect findings distinguish observation from proof. A finding records category, confidence, severity, source, scope, evidence references, observation time, and disposition. An anomaly alone is not equivalent to confirmed malicious activity.

Supported disposition values include `informational`, `suspicious`, `likely_malicious`, `confirmed_malicious`, and `unknown`.

## Scan finding

Wardveil Scan records the inspected object class, object reference, scanner capability/version, result, finding categories, evidence references, observation time, and validity boundary when the result is reused.

Canonical scan results are `clean`, `suspicious`, `malicious`, `unknown`, and `unsupported`. `unknown` and `unsupported` must never be interpreted as clean.

## Protection action

Wardveil Protect records the policy or finding that authorized the action, requested action class, executor identity, exact target scope, authorization time, expiry, idempotency key, execution status, result evidence, and audit correlation identifier.

High-impact actions such as session revocation, credential disablement, isolation, quarantine, or account restriction require explicit executor authority. A stale or ambiguous action request fails closed.

## Quarantine record

Wardveil Quarantine records the isolated object reference, source application, reason, triggering finding or policy decision, isolation time, review state, allowed review actions, retention/expiry semantics, and audit correlation identifier.

Quarantine is not deletion. Release, restoration, removal, or destructive handling requires an explicit authorized action and audit record.

## Incident record

Wardveil Response records incident identity, severity, status, affected scopes, correlated findings, containment actions, assigned authoritative executors, notifications, remediation state, recovery dependencies, timeline references, and post-incident verification state.

Cross-system response coordination does not transfer authority. Each mutating action identifies the executor that actually owns and performs the technical change.

## Audit event

Wardveil Audit records material authentication, authorization, trust, policy, detection, scan, protection, quarantine, response, administrative, and security-sensitive application events. Records include actor class, event type, represented scope, source, timestamp, correlation identifiers, outcome, and evidence references.

Audit records must be integrity-protected or tamper-evident according to the implementation environment. Audit storage must not become a secret repository.

## Security Center consumption

Wardveil Security Center consumes normalized records and evidence references. It may present protection state, trust state, threats, sessions/devices, quarantine, incidents, policies, recommendations, and audit history, but presentation itself is not proof that a control executed successfully.

## Application integration rule

A first-party GoreeCloud application integrating with Wardveil should use these contracts for supported security interactions instead of inventing local equivalents. The application must preserve producer identity, scope, freshness, and authority boundaries and must fail closed when a required contract cannot be validated.
