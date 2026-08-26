# Wardveil Runtime Acceptance Evidence

This document defines the evidence model used to determine whether the Cloudflare persistence runtime has actually satisfied Wardveil's production acceptance contract.

## Principle

Deployment success is not runtime acceptance. A healthy `/healthz` response is not proof that internal mutation paths, retention, recovery, or observability requirements work. Storage health is not a Wardveil protection claim.

Runtime acceptance is granted only when one evidence manifest for one exact deployed revision satisfies every required check in `contracts/wardveil.cloudflare.runtime-acceptance.json`.

## Required Evidence

The manifest must identify the exact deployed Git revision and record bounded evidence for:

- deployed revision match;
- public `/healthz` reachability;
- authorized service-binding append and read;
- duplicate-record rejection;
- checkpoint non-regression;
- retention-alarm execution;
- persisted payload digest verification;
- PITR availability;
- an independently performed restore-verification exercise;
- observability evidence demonstrating a detectable runtime failure path; and
- absence of a generic public mutation surface.

Each check must record `status`, `observed_at`, `source`, and a human-readable evidence summary. Evidence values are operational evidence only and cannot manufacture, extend, reinterpret, or upgrade Wardveil security state.

## Acceptance States

- `unaccepted`: required live evidence has not been collected or one or more required checks are missing.
- `degraded`: evidence collection completed but one or more required checks failed, expired, or became unavailable.
- `accepted`: every required check passed for the exact deployed revision and the manifest itself passed validation.

Acceptance is revision-bound. A new deployment requires a new evidence manifest. Prior acceptance may be useful historical evidence but cannot automatically accept a different source revision.

## Service-Binding Test Boundary

Internal append/read and checkpoint tests must run through an authenticated Cloudflare service binding or equivalent private RPC relationship. The acceptance harness must not create a generic public record-mutation endpoint merely to make testing easier.

A test record must be explicitly synthetic, contain no production credential, secret, private key, authentication header, raw private activity, or unnecessary identifier, and must use a bounded test tenant/resource scope.

## Retention and Recovery

Retention-alarm evidence proves that retention enforcement executed; it does not prove all records were deleted according to policy unless the test also verifies the expected record lifecycle.

PITR availability proves that the storage platform exposes recovery capability. It is not a successful recovery exercise. Restore verification must be represented separately and remains subject to Everkeep's resilience and recovery authority.

## Observability

Acceptance requires evidence that a deliberately bounded failure is visible through the configured operational observability path. The test must not induce an uncontrolled production outage. A failed or rejected synthetic operation is sufficient when the resulting log, alert, or evidence proves the failure path is observable.

## Security Center Boundary

Security Center may display persistence-runtime acceptance and degradation as infrastructure health evidence. It must not convert runtime acceptance into `Protected by Wardveil`, trust, authorization, malware-cleanliness, or incident-closure claims.
