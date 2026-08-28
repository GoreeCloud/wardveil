# Wardveil Quarantine Executor

Wardveil Foundation 0.9 now has a source-level first high-impact Protect executor dedicated to `quarantine`. The executor composes existing Wardveil Policy, runtime authorization, service identity, durable execution state, Quarantine, Audit, and Security Center contracts without treating any one of those layers as substitute authority for the resource owner.

## Execution sequence

The reference sequence is:

1. Validate an authoritative current Wardveil Policy record whose action is exactly `quarantine`.
2. Verify the signed execution authorization, issuer identity, executor identity, signing-key ID, policy digest, scope, correlation, action, and validity window.
3. Durably claim the exact authorization before the target side effect.
4. Invoke the explicitly bound quarantine target with an operation ID derived from the full authorization digest.
5. Require exact target-state readback before recording quarantine as succeeded.
6. Persist an authoritative Wardveil Protect receipt.
7. Produce a non-destructive `quarantine_record` in `pending` review state and a Wardveil Audit event carrying bounded nonsecret authorization provenance.
8. Allow Security Center to surface issuer, executor, authorization, and signing-key IDs for forensic provenance without treating that metadata as protection evidence.

A target timeout, ambiguous response, failed readback, or persistence loss after a possible side effect does not authorize a blind retry. The durable claim remains reconciliation-required and the original authorization remains non-reusable.

## Target-side authority and idempotency

The target adapter remains authoritative for the resource's actual quarantine state. A signed Wardveil authorization, service binding, or durable claim does not grant the executor ownership of the target resource.

Target execution must support an operation identity bound to the authorization digest. A repeated exact operation may report `already_applied` only when the target can prove it is the same quarantine operation. A conflicting existing state fails closed. Successful mutation without matching target readback is not sufficient for a successful Wardveil Protect result.

The initial source contract recognizes the resource types already used by executable Wardveil Scan consumers: `mail_attachment`, `drive_file`, `browser_download`, and `ai_artifact`. This list is an integration contract, not evidence that a production quarantine adapter is deployed for all four resource types.

## Quarantine is not deletion

A successful execution creates or confirms quarantine state; it does not delete content. The canonical Wardveil `quarantine_record` begins in `pending` review state with `destructive_action=false`. Release requires separate explicit release authority. Removal requires separate explicit destructive authority.

## Audit and Security Center provenance

The Audit reference can hash-bind these nonsecret fields into an audit event:

- `authorization_id`
- `issuer_id`
- `executor_id`
- `signing_key_id`
- `signature_algorithm`

Signing-key material, credentials, bearer tokens, session material, and raw resource content remain prohibited. Security Center can surface this provenance from authoritative audit records, but provenance does not independently create or upgrade a `Protected by Wardveil` state.

## Cloudflare source candidate

`cloudflare/quarantine-executor/` contains a WorkerEntrypoint source candidate. Its execution method is Worker RPC only. The fetch handler returns `404`, `workers_dev` and preview URLs are disabled, and no public `/execute` or generic mutation endpoint is defined.

The candidate uses the existing `goreecloud-wardveil-persistence` service binding for durable claims and receipts and requires a separate `WARDVEIL_QUARANTINE_TARGET` service binding for the resource-owner adapter. That target binding is intentionally `REPLACE_AT_DEPLOYMENT` in source so repository code cannot silently invent or claim an authorized production target. The Worker refuses execution while the placeholder remains.

The current HMAC verification secret exists only to preserve conformance compatibility with the Foundation 0.9 reference authorization scheme. It is not approved production cryptography or production key management.

## Cloudflare deployment gate

`.github/workflows/deploy-cloudflare-quarantine-executor.yml` and `contracts/wardveil.quarantine-executor-deployment.json` define the controlled deployment gate for the source candidate. This workflow is manual, main-branch-only, exact-revision-bound, and attached to the `wardveil-production` GitHub environment. It does not make deployment equivalent to production acceptance.

A dispatch must provide a real existing target Worker and an explicit least-privilege subset of `mail_attachment`, `drive_file`, `browser_download`, and `ai_artifact`. The workflow rejects `REPLACE_AT_DEPLOYMENT`, rejects Wardveil control-plane Workers as target resource authorities, rejects empty/duplicate/unknown resource types, and verifies both the selected target Worker and `goreecloud-wardveil-persistence` already exist before the executor is deployed. This follows the Cloudflare service-binding requirement that a downstream Worker exist before a Worker that binds to it is deployed.

The generated production Wrangler configuration is ephemeral. It replaces only the deployment target and the explicitly approved resource-type subset while preserving `workers_dev=false`, `preview_urls=false`, and `WARDVEIL_PRODUCTION_RUNTIME_STATUS=unaccepted`. It is deleted after the workflow. The tracked source configuration keeps its placeholder so a target identity is never silently promoted into repository truth.

`WARDVEIL_AUTH_VERIFICATION_KEY` must be pre-provisioned as an encrypted Worker secret. The deployment workflow checks only the secret name through Wrangler and never reads, prints, writes to source, or copies the secret value into the generated configuration. The workflow deliberately does not run `wrangler secret put`, because secret bootstrap/rotation is a separate controlled key-management operation.

After deployment, `cloudflare/quarantine-executor-acceptance-runner/` starts only on loopback and calls the deployed executor through a remote Cloudflare service binding. Its probe is intentionally non-mutating: it submits a deliberately invalid policy and requires the exact `invalid_policy_record` rejection. Because the executor checks its deployment target before policy parsing, this proves that internal RPC reaches a deployed executor whose source placeholder has been replaced, without creating a valid execution authorization or invoking the target quarantine adapter.

The deployment evidence manifest stays `unaccepted`. A successful deployment and non-mutating transport probe still do not prove the selected target implements the required idempotency/readback interface, that a quarantine side effect succeeded, that production cryptography/key lifecycle is accepted, or that Privacy Shield/Everkeep requirements are satisfied.

## Privacy Shield and Everkeep boundaries

The executor requires only minimized scope, authorization metadata, policy evidence references, target-state references, and bounded quarantine reason metadata. Raw file bodies, attachment contents, URLs, user-facing filenames, credentials, tokens, and signing secrets are not required by the shared execution record. Privacy Shield remains the privacy and minimization authority.

Everkeep remains GoreeCloud's resilience, recovery, backup, and restore-verification authority. Quarantine does not delete or overwrite recovery material, and later recovery or restore claims require their own Everkeep evidence.

## Production acceptance

Production runtime status remains `unaccepted`. Source tests, TypeScript compilation, a successful gated Worker deployment, and a non-mutating internal transport probe do not prove deployed quarantine enforcement.

Acceptance still requires approved production signature verification and key management, production service identity, least-privilege inbound service bindings, a real authorized quarantine target binding, deployed durable claim/receipt storage, target-side idempotency and readback evidence from an authorized controlled quarantine exercise, recovery-safe persistence of Quarantine and Audit evidence, key rotation/revocation exercises, crash/replay/tamper/timeout/conflict/persistence-failure tests, Security Center runtime provenance, quarantine release/recovery evidence, Privacy Shield acceptance, and applicable Everkeep acceptance.
