# Wardveil Platform API V1

**Status:** Weave source contract. Production API acceptance remains unaccepted.

Wardveil exposes a narrow private API path for first-party service integration through the deployable Cloudflare persistence Worker. The supported API version is `wardveil-persistence-rpc/v1`.

## Transport

The application API is Cloudflare Worker service-binding/RPC, represented in the Platform Contract as:

`service-binding://goreecloud-wardveil-persistence`

This is a symbolic private service-binding reference, not a public Internet URL. A production consumer must use an approved authenticated service binding and accepted GoreeCloud Identity/service identity.

Public HTTP remains bounded to:

- `GET /healthz` — liveness only.
- `GET /readyz` — readiness that exercises the Durable Object/storage/schema path.

There is no generic public mutation API.

## Application RPC surface

The supported application RPC methods are:

- `append`
- `readAfter`
- `checkpoint`
- `getCheckpoint`
- `claimExecutionAuthorization`
- `finalizeExecutionAuthorization`
- `getExecutionReceipt`
- `health`
- `maintenanceEvidence`

Two Worker methods are acceptance-only and are not general application API:

- `scheduleAcceptanceRetentionAlarm`
- `emitAcceptanceObservabilityFailure`

They exist solely for bounded exact-deployment acceptance and observability exercises.

## Authority boundary

An authenticated API call does not create Wardveil execution authority, target-system authority, Protected/Covered status, or production acceptance.

Persistence remains non-authoritative for security semantics. Wardveil runtime authorization and the target executor's own action/resource authorization are separately required for high-impact actions.

The API must not expose or accept a public bearer-token mutation surface as a substitute for approved service identity. Reusable credentials, private keys, signing secrets, and raw private content remain outside ordinary shared records and API evidence.

## Production boundary

The source contract is implemented and validated, but production API acceptance remains **unaccepted** until the exact deployed runtime has accepted service identity, authenticated private transport, live dependency/readiness evidence, failure/retry behavior, observability, recovery, and release qualification.
