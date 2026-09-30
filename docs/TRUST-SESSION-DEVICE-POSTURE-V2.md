# Wardveil — Trust, Session, and Device Posture V2

**Work package:** K  
**Lifecycle:** source-level Development candidate  
**Authority:** Wardveil Trust evidence for Policy only

## Core boundary

**Trust is not authorization.** A trustworthy session, device, service, or user may still lack permission to perform an operation. This Work Package does not mint execution authorization, transfer target authority, prove execution success, or create a Protected state.

## Operation-scoped trust

Trust is evaluated for one exact operation scope. The source contract binds the subject, device, session, runtime, application, requested action, impact level, observation time, expiration time, and individual evidence inputs. No global trust state is created, and an accepted operation cannot make the same subject universally trusted for later operations.

The supported trust states are **Trusted**, **Restricted**, **Unknown**, **Untrusted**, and **Reauthentication Required**.

## Evidence visibility

Each trust input has an explicit state:

- `present` — bounded evidence is available from the named authority;
- `missing` — required evidence is unavailable;
- `stale` — evidence exists but is not fresh enough;
- `conflicting` — authoritative inputs disagree;
- `invalid` — the evidence cannot be validated for the requested operation.

A present input requires an evidence reference. Missing, stale, conflicting, and invalid states remain visible so Security Center can distinguish lack of evidence from evidence of compromise.

## Freshness and high-impact operations

Evidence is time-bounded. The reference evaluator rejects future observations and invalid validity windows. High-impact operations use a stricter five-minute freshness ceiling in this source candidate; other bounded operations use a fifteen-minute ceiling. These are source-model defaults, not production SLO claims. Production thresholds require separate runtime measurement and acceptance.

Expired or too-old evidence cannot preserve Trusted. The evaluator returns Unknown unless stronger negative evidence requires a more restrictive state.

## Re-evaluation triggers

The bounded source model recognizes explicit triggers for:

- session revocation;
- compromised credentials;
- runtime integrity failure;
- material posture change; and
- a material security incident.

Session revocation requires Reauthentication Required. Credential compromise, runtime-integrity failure, conflicting/invalid evidence, or a material security incident results in Untrusted. A material posture change without stronger failure evidence results in Restricted. Missing or stale evidence results in Unknown.

## Authority preservation

The result always records:

- `authorization_effect: false`;
- `execution_authorization: false`;
- `target_authority: false`; and
- `global_trust: false`.

Applications and Wardveil Policy may use the evaluated trust state as one bounded input. They may reduce privilege further, but trust must never be converted directly into permission or proof that an external action succeeded.

## Acceptance boundary

Work Package K is source-level Development work only. It does not establish production trust acceptance. It also does not establish production GoreeCloud Identity acceptance, live session/device telemetry, accepted device-integrity providers, production runtime validation, Security Center live adoption, target-environment acceptance, production acceptance, Stable qualification, or a broader `Protected by Wardveil` claim.
