# Wardveil Cloudflare Deployment and Acceptance

This document defines the deployment and acceptance boundary for the Wardveil Security persistence Worker and SQLite-backed Durable Object adapter.

## Deployment unit

- Worker: `goreecloud-wardveil-persistence`
- Durable Object binding: `WARDVEIL_PERSISTENCE`
- Durable Object class: `WardveilPersistenceDO`
- Storage: SQLite-backed Durable Object storage
- Public HTTP surface: health/readiness only
- Mutation surface: authenticated Cloudflare service binding / RPC only

## Required deployment properties

Production dispatch is controlled from authoritative `main`, but the deployed bytes are not inferred from the workflow-control commit. The workflow requires `expected_sha` to exactly match `qualification/seal-candidate.json#source_revision`, proves that candidate is an ancestor of the governing `main` revision, then checks out and deploys that exact Seal source. Runtime evidence records both the Seal source/deployed revision and the separate workflow-control revision.

A production candidate must preserve the repository `cloudflare/wrangler.jsonc` configuration or an explicitly reviewed environment-specific derivative from that declared Seal source, including the SQLite Durable Object migration, service-binding-first mutation boundary, explicit compatibility date, observability configuration, and absence of secrets in source control.

Production acceptance requires evidence that: the deployed Worker revision matches an accepted repository revision; `/healthz` reports the expected schema and bounded storage-health state; authorized internal RPC can append/read records; duplicate IDs fail safely; consumer checkpoints cannot regress; retention alarms create maintenance evidence without rewriting surviving records; payload digests verify after readback; PITR availability is distinguished from restore verification; observability captures Worker/Durable Object failures; and no public endpoint grants generic write, checkpoint, retention, migration, or recovery authority.

## Security boundary

Cloudflare storage, encryption-at-rest, transport security, PITR availability, health status, and successful deployment are infrastructure evidence only. They do not create, extend, reinterpret, or upgrade Wardveil Trust, Policy, Protect, Detect, Scan, Quarantine, Response, Audit, or Security Center state.

A successful `/healthz` response means the persistence adapter is reachable and can report its own bounded storage health. It does **not** mean a user, account, session, device, file, application, service, or infrastructure resource is protected by Wardveil.

## Recovery boundary

PITR availability is not restore verification. Recovery acceptance requires an explicit recovery exercise against a safely isolated target, integrity verification after restoration, checkpoint/record consistency checks, and evidence suitable for Everkeep coordination. Everkeep remains GoreeCloud's resilience and recovery authority.

## Production acceptance state

Source validation and Cloudflare Pages preview success do not prove that the Worker/Durable Object backend has been deployed or accepted in production. A newer workflow-control commit also does not silently replace the frozen Seal source being qualified. Until live exact-candidate Worker evidence is collected, production runtime status remains **unaccepted**.

## October 4, 2026 deployment attempt

GitHub Actions workflow run `37236563970` exercised the corrected exact-candidate deployment guard from authoritative `main` revision `5a9611f4da2c954274ef1d35c64ec13823bce190`.

The workflow:

- validated `expected_sha` against the declared Seal source;
- verified the Seal source was an ancestor of the governing workflow-control revision;
- checked out exact candidate `cc493530c02925a4404c54d2767c15d9fbfa0835`; and
- verified the exact candidate checkout.

It then failed closed at the required environment-value check because `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, and `WARDVEIL_HEALTH_URL` were unavailable. All deployment and evidence-collection steps were skipped.

Therefore no Cloudflare Worker was deployed, no production runtime state changed, and no runtime acceptance evidence was created. The next action is authorized provisioning of the required `wardveil-production` environment values followed by a fresh exact-candidate workflow dispatch.

## October 13, 2026 production deployment and qualification observations

An authorized exact-candidate deployment-and-acceptance attempt from GitHub Actions `main` advanced beyond the October 4 missing-secrets blocker. The owner provisioned the three required names in the `wardveil-production` environment; secret values were not retrieved or retained in acceptance evidence.

- Governance/control revision: `2b47ceab7316e0a9196f5ce53c1d8fc13b6ae637` (PR #212 corrected an isolated pinned Wrangler 4.37.0 installation issue).
- Frozen candidate/deployed source revision: `cc493530c02925a4404c54d2767c15d9fbfa0835` (unchanged Seal source).
- [Initial deployment run #38471274185](https://github.com/GoreeCloud/wardveil/actions/runs/38471274185) deployed both Workers but failed after an unexpected HTTP 500 from the public negative mutation probe; later independent HTTPS requests returned HTTP 404.
- [Re-run #38471548668](https://github.com/GoreeCloud/wardveil/actions/runs/38471548668) deployed the persistence Worker (reported Cloudflare version `16ae7dc9-435e-40af-b826-8554d5a24744`) and non-public acceptance probe (reported version `70766cd3-f59a-4561-9544-f7754d364cc1`). The run advanced through public health/readiness and public mutation-surface checks and started a local-only acceptance runner. It was cancelled after the job's 20-minute limit while awaiting `POST /run` in the `Collect privileged service-binding and retention evidence` step (started 21:34:16 UTC). It **did not** produce passed evidence for authenticated append/read, checkpoint non-regression, digest readback, the retention alarm, or privileged observability.
- Independent read-only HTTPS checks from the authorized GoreeCloud VPS and laptop around 22:00 UTC observed `GET /healthz` HTTP 200 (`alive`), `GET /readyz` HTTP 200 (`ready`), and `GET /records` HTTP 404. These are point-in-time observations of public reachability only.
- [PR #213](https://github.com/GoreeCloud/wardveil/pull/213) introduces bounded, fail-closed HTTP request timeouts and is subject to governed merge before any new qualification run. [Issue #214](https://github.com/GoreeCloud/wardveil/issues/214) tracks the unresolved private binding timeout.

**Qualification boundary:** The Worker deployment and public smoke checks are confirmed. Cloudflare production runtime acceptance remains **unaccepted** and the `cloudflare-runtime-acceptance` Seal/Anchor gate remains blocked. A bounded, exact-source private service-binding run with real positive and negative evidence, a separate Everkeep-governed isolated restore exercise, and the remaining lifecycle gates are required. The Cloudflare Worker being alive/ready cannot be interpreted as a `Protected by Wardveil` claim or Anchor promotion.
