# Wardveil Cloudflare Runtime Operations

This document defines the deployment and runtime-acceptance procedure for the Wardveil Cloudflare persistence Worker and SQLite-backed Durable Object adapter.

## Deployment authority boundary

Source acceptance, deployment evidence, storage health, and Wardveil security-state authority are separate concerns.

- A successful GitHub Actions deployment proves only that the approved source revision was submitted to Cloudflare successfully and that the workflow's post-deployment checks passed.
- Storage health does not create or upgrade a `Protected by Wardveil` claim.
- A successful `/healthz` response proves only Worker liveness. A successful `/readyz` response additionally proves the Worker can reach its Durable Object binding and that the bounded schema/storage health path reports operational; neither proves service-binding authorization, durable-record correctness, retention enforcement, PITR recovery, incident recovery, or protection authority.
- Cloudflare does not become authoritative for Wardveil Trust, Policy, Protect, Detect, Scan, Quarantine, Response, Audit, or Security Center semantics merely by hosting persistence.
- Everkeep remains GoreeCloud's resilience and recovery authority. PITR availability is not restore verification.

## Production environment

The deployment workflow uses the GitHub Environment `wardveil-production`. Production deployment must remain manual through `workflow_dispatch` until an explicitly reviewed release automation contract replaces it.

Required environment secrets:

- `CLOUDFLARE_API_TOKEN` — scoped Cloudflare credential authorized only for the required Worker/Durable Object deployment operations.
- `CLOUDFLARE_ACCOUNT_ID` — the target GoreeCloud Cloudflare account identifier.
- `WARDVEIL_HEALTH_URL` — canonical HTTPS URL ending in `/healthz` for the deployed Worker.

Secrets must not be committed to the repository, emitted into logs, stored in Wardveil records, or copied into Google Drive documentation.

## Exact-revision deployment

A production operator supplies the exact approved `main` commit SHA as the `expected_sha` workflow input. The workflow fails closed unless:

1. the workflow is dispatched from `main`;
2. `GITHUB_SHA` exactly equals `expected_sha`;
3. the checked-out repository revision exactly equals that SHA;
4. all required deployment secrets are present;
5. the health URL is HTTPS and terminates in `/healthz`.

The workflow installs the exact Wrangler release declared by the deployment contract and deploys `cloudflare/wrangler.jsonc`.

## Immediate post-deployment checks

The deployment workflow performs two bounded public checks:

1. `/healthz` must answer successfully and identify `goreecloud-wardveil-persistence`.
2. `/readyz` must answer successfully and report `ready` after exercising the Durable Object/storage/schema path.
3. a generic public `POST /records` mutation attempt must remain unavailable and return HTTP 404 or 405.

These checks verify the public exposure boundary only. They do not exercise privileged service-binding/RPC methods.

## Full runtime acceptance

The authoritative evidence set remains `contracts/wardveil.cloudflare.runtime-acceptance.json`.

Full production runtime acceptance requires independent evidence for:

- deployed revision match;
- health endpoint;
- readiness endpoint;
- authorized append/read through the intended service-binding identity;
- duplicate-record rejection;
- consumer-checkpoint non-regression;
- retention alarm execution and retention enforcement;
- persisted payload-digest verification;
- PITR availability;
- a separate restore-verification exercise coordinated with Everkeep;
- observability evidence for a controlled failure path;
- absence of a generic public mutation surface.

No workflow may set `production_runtime_status` to accepted solely because deployment or health checks succeed.

## Service-binding acceptance probe

Privileged acceptance should be performed from an explicitly authorized GoreeCloud service binding rather than from a public HTTP endpoint. The probe must use non-sensitive synthetic records and demonstrate:

1. append of one authoritative synthetic record;
2. read-back with exact record identity and payload digest;
3. rejection of a duplicate record ID;
4. checkpoint advancement;
5. rejection of checkpoint regression;
6. verification that another unauthorized service identity cannot perform the same mutation.

Acceptance probe data must be clearly marked synthetic and must not contain credentials, private keys, tokens, personal data, or production security evidence.

## Retention and recovery acceptance

Retention acceptance requires evidence that the Durable Object alarm executes and removes only records whose bounded retention class has actually expired. It must not reinterpret producer security-evidence validity.

Recovery acceptance requires two distinct pieces of evidence:

- Cloudflare PITR capability/bookmark availability; and
- an exercised restore that is verified independently and recorded through the Everkeep recovery boundary.

PITR capability alone is never equivalent to a successful recovery exercise.

## Observability acceptance

A controlled non-destructive failure must be generated through an authorized test path so the runtime can demonstrate that the failure is observable without exposing secrets or sensitive payloads. The evidence should identify the deployed source revision, component, bounded test scope, timestamp, and resulting operational signal.

## Rollback

Rollback must target a previously accepted repository revision rather than an arbitrary build artifact. The same exact-revision workflow is used with the approved rollback commit SHA. A rollback deployment does not automatically restore application data; any data recovery remains governed by Everkeep and the applicable persistence recovery procedure.

## Acceptance state

Until every required runtime-acceptance evidence item is collected and reviewed, the canonical machine-readable status remains:

`production_runtime_status = unaccepted`

This is a fail-closed acceptance state, not a claim that the adapter is unusable or insecure. It means production acceptance has not yet been completely demonstrated.
