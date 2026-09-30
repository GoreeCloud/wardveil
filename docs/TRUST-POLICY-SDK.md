# Wardveil Trust + Policy Reference SDK

Wardveil Trust and Wardveil Policy form the decision foundation of the Wardveil security plane. The dependency-free implementation in `reference/wardveil_decision.py` is a deterministic reference for how GoreeCloud applications can construct trust inputs, obtain a Wardveil trust state, evaluate a policy decision, and serialize those decisions into the canonical runtime security contract.

It is not a production authentication provider, authorization server, device-attestation service, geolocation engine, or threat-intelligence source. Applications remain responsible for supplying current authoritative signals through explicit integration contracts.

## Decision chain

`Identity -> Authentication -> Device and Session Evidence -> Wardveil Trust -> Wardveil Policy -> Authorized Executor`

Trust is not authorization. A `trusted` trust state describes the evaluated evidence for the represented scope; Wardveil Policy still decides whether the requested operation may proceed.

## Reference inputs

`AccessRequest` contains the principal class, target resource, operation, source producer, requested privilege, resource sensitivity, and a bounded set of `TrustSignal` records. Each trust signal declares whether it is authoritative, an optional non-secret evidence reference, and an explicit non-negative risk contribution.

Signals are deliberately generic so applications can map supported GoreeCloud Identity, device, session, application-integrity, compromise, and detection evidence without embedding credentials or raw private activity in Wardveil records.

## Fail-closed behavior

The reference engine restricts access when required trust evidence is absent or unverified. Confirmed compromise produces a blocked trust state. Material device-integrity failure or very high accumulated risk produces restricted state. Expired trust decisions cause Policy to block rather than silently reuse stale evidence.

The engine never upgrades a missing or unverified signal into a favorable decision.

## Explainability

Trust and policy results carry reason codes and evidence references. This keeps security decisions inspectable without exposing reusable secrets, private keys, session tokens, raw authentication material, or unnecessary personal data.

## Policy behavior

The reference policy demonstrates conservative defaults rather than claiming to be the final organization policy engine. It blocks blocked trust, restricts restricted trust, requires step-up verification for privileged or highly sensitive operations when trust is insufficient, warns on elevated-risk ordinary operations, and emits `allow_and_log` for selected sensitive operations when the trust state is fully trusted.

Applications must not interpret the reference defaults as permission to bypass their own authorization rules. Product-specific policy sets can be stricter and remain authoritative for their defined scope.

## Runtime records

`TrustDecision.as_runtime_record()` emits a `trust_decision` record and `PolicyDecision.as_runtime_record()` emits a `policy_decision` record compatible with `contracts/wardveil.runtime.schema.json`. Records include scope, producer, observation time, validity deadline, evidence references, and correlation identifiers.

## Acceptance boundary

The reference SDK proves deterministic contract behavior and provides a reusable implementation starting point. It does not establish production deployment, product-specific runtime acceptance, Stable qualification, or authorization for a GoreeCloud application merely because the application imports the module. Those claims require integration-specific evidence and testing.
