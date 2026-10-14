# Wardveil Cloudflare Runtime Evidence Collection

This document defines the guarded collection path for live Wardveil Cloudflare persistence evidence after the persistence Worker and internal acceptance probe are deployed.

## Collection model

The production deployment workflow deploys the persistence Worker and the non-public `goreecloud-wardveil-acceptance-probe` on one exact approved `main` revision. It then starts a local-only Wrangler acceptance runner inside GitHub Actions. The runner uses a Cloudflare remote service binding to call the deployed acceptance probe without introducing a public acceptance-probe route.

The deployed acceptance probe in turn calls `goreecloud-wardveil-persistence` through its internal service binding. This preserves the production service-to-service path while keeping record mutation unavailable through the generic public HTTP surface.

Cloudflare remote bindings are a development/testing transport mechanism for reaching deployed resources from locally executing Worker code. They do not make the target Worker public and do not transfer Wardveil security authority to Wrangler, GitHub Actions, or Cloudflare transport.

## Evidence collected in one guarded run

One successful deployment-and-collection run can establish revision-bound evidence for:

- exact deployed revision matching;
- the canonical persistence `/healthz` endpoint;
- authorized service-binding append/read;
- duplicate-record rejection;
- consumer-checkpoint non-regression;
- persisted payload-digest verification;
- Durable Object PITR capability/bookmark availability;
- execution of the real Durable Object retention `alarm()` handler in the dedicated acceptance tenant;
- a bounded failure-path marker independently observed through Cloudflare Worker tail evidence; and
- absence of a generic public `POST /records` mutation surface.

Acceptance records are `test_only`, use the `transient` retention class, and are scoped to the dedicated `wardveil-runtime-acceptance` tenant. Shortened alarm scheduling is accepted only for that tenant; it cannot target arbitrary production tenants. The bounded observability exercise deliberately fails without mutating a production record and must be corroborated by Cloudflare tail output rather than by the probe's return value alone.

The acceptance alarm still uses Cloudflare's normal Durable Object alarm mechanism and the production retention handler. The shortened schedule exists only to make the acceptance exercise bounded; it does not replace the normal six-hour maintenance schedule or create a second retention implementation.

## Producer-declared freshness

The deployment workflow reads `evidence_validity_seconds` from `contracts/wardveil.cloudflare.runtime-acceptance.json`. The governed value is 3600 seconds. At manifest construction time the producer records `collected_at` and computes `valid_until` exactly one hour later.

The deadline is part of Wardveil's acceptance evidence, not a consumer preference. GoreeCloud Mesh and other consumers may reject evidence after `valid_until`, but they must not extend or replace the deadline. A later deployment or later evidence collection requires a new revision-bound manifest; historical evidence does not regain currency merely because it remains stored or visible.

The source-controlled production template is deliberately expired and uses a placeholder revision. It is contract scaffolding only and cannot satisfy current-evidence queries.

## Historical Workers Logs readback — separate least-privilege identity

A live Cloudflare Worker tail session can fail to attach or deliver a particular marker. Historical stored-event readback is a separate, supplemental evidence path; neither a probe acknowledgement nor an empty live tail is sufficient to assert that the event was observed.

On October 14, 2026, [governed nonpromoting readback run #38560325264](https://github.com/GoreeCloud/wardveil/actions/runs/38560325264) reached the Cloudflare API but received HTTP **403** when using the existing short-lived `CLOUDFLARE_API_TOKEN` Workers Admin deployment credential. The local verifier self-test passed. The 403 is consistent with the documented additional Workers Observability API permission; it is not evidence that the marker is absent or that the Worker failed. [Cloudflare's query endpoint](https://developers.cloudflare.com/api/resources/workers/subresources/observability/subresources/telemetry/methods/query/) requires **Workers Observability Write**, even to run a historical readback query.

Do not expand or reuse the deployed Worker administrator's token. For authorized historical readback, the owner must independently create a **separate, short-lived Cloudflare API token** scoped to the selected GoreeCloud account with only `Workers Observability Write`, then store its value directly under the exact GitHub **environment secret name** `CLOUDFLARE_OBSERVABILITY_API_TOKEN` in `GoreeCloud/wardveil` → `wardveil-production`. Do not send the value in chat, copy it into source, or attach it to task records. Token creation and permission changes are owner actions; this repository does not generate or broaden tokens.

The manual workflow `.github/workflows/verify-cloudflare-historical-observability.yml` queries only historical `cloudflare-workers` events. It uses the separate observability token, the existing account ID, an exact synthetic marker, and an owner-selected bounded UTC window (at most 30 minutes). The verifier requires a completed Cloudflare query and the exact marker in a record attributed to `goreecloud-wardveil-persistence`. It does not output raw events or upload artifacts; a nonmatch, missing token, 403, or unexpected API response fails closed.

The known historical target from [production run #38558212925](https://github.com/GoreeCloud/wardveil/actions/runs/38558212925) is marker `acceptance-ebb6c624-69dd-4364-bc66-f282b2a6e5e1` around October 14, 2026, 11:41 UTC. Stored-log availability is subject to Cloudflare retention, sampling and account entitlement. A later independent readback does **not** retroactively convert the failed original workflow run to success or promote the Seal candidate. Reconciliation must be documented under the exact source/workflow revisions and independently verified by the release process.

## Evidence intentionally left pending

The deployment workflow must not self-certify recovery authority. After the expanded runtime probe and independent Cloudflare tail observation complete, the remaining acceptance requirement is:

- an Everkeep-governed restore-verification exercise against the same exact deployed revision.

PITR availability is not restore verification. Deployment success is not runtime acceptance. Storage health is not evidence that an identity, session, device, file, account, application, service, or other resource is Protected by Wardveil.

## Acceptance-state boundary

The workflow emits a machine-readable revision-bound evidence manifest into the GitHub Actions log and job summary. The manifest must remain `acceptance_status: unaccepted` until every required check in the canonical Cloudflare runtime-acceptance contract has passed for the same exact deployed revision.

The internal acceptance probe itself may report only `unaccepted` or `degraded`; it has no capability to promote production status to `accepted`. Even when retention and observability exercises pass, Everkeep restore verification remains a separate acceptance authority.

A manifest that eventually reaches `accepted` would still be current only until its producer-declared `valid_until`. Transporting an accepted manifest does not establish broad Wardveil production acceptance or any resource-level protection, trust, authorization, cleanliness, incident, or recovery claim.

## Authority boundaries

Wardveil remains authoritative only for Wardveil-native security records and semantics within its declared scope. Cloudflare provides infrastructure and transport. GoreeCloud Mesh provides coordination. Privacy Shield remains the privacy and minimization authority. Everkeep remains the resilience, backup, restore, and recovery-verification authority.

No evidence-collection workflow may manufacture, extend, reinterpret, or upgrade security state, producer evidence validity, incident closure, malware cleanliness, authorization, trust, or a Protected by Wardveil claim.
