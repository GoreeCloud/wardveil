# Wardveil Security by GoreeCloud

Wardveil Security is GoreeCloud's platform-wide first-party security system and shared security plane. It coordinates evidence-backed trust, policy, protection, detection, scanning, quarantine, incident response, audit, and security-center experiences across GoreeCloud.

> **Current status:** Seal under Platform Contract 2.0. Exact candidate `wardveil-0.9.0-seal.1` freezes Foundation 0.9 implementation source at `cc493530c02925a4404c54d2767c15d9fbfa0835`. Deployment remains development and Anchor qualification is blocked on the gate groups in `qualification/seal-readiness.json`. The Seal transition does not create a `Protected by Wardveil` claim, production runtime acceptance, or Anchor authority; any material runtime, dependency, security, recovery, supported-platform, or release-critical configuration change supersedes this candidate.

## First-party security capabilities

Wardveil Security is the umbrella system for nine cooperating capabilities:

- **Wardveil Trust** — identity, session, device, service, and contextual risk evaluation.
- **Wardveil Protect** — preventive controls, enforcement, and active protection.
- **Wardveil Detect** — threat, abuse, behavioral, and anomaly detection.
- **Wardveil Scan** — file, content, package, URL, attachment, download, and payload inspection.
- **Wardveil Policy** — central security policy, rules, decisions, and enforcement logic.
- **Wardveil Quarantine** — isolation, containment, review, release, and remediation.
- **Wardveil Audit** — security evidence, events, decisions, and history.
- **Wardveil Response** — incident containment, remediation, escalation, and recovery coordination.
- **Wardveil Security Center** — unified user and administrator protection experience.

These are substantive first-party security capabilities, not decorative labels. Their canonical responsibility and authority boundaries are defined in `docs/ARCHITECTURE.md` and `contracts/wardveil.capabilities.json`. Their detailed intended feature scope is defined in `docs/FEATURES.md`.

## Security lifecycle

A representative lifecycle is:

`Trust -> Policy -> Protect -> Detect -> Scan -> Quarantine -> Response -> Audit`

The lifecycle is not strictly linear. Components may invoke or inform one another as evidence changes. Wardveil Security Center spans the lifecycle as the human-facing visibility and control layer.

## Core security invariants

Wardveil follows evidence before reassurance. Protected state requires current authoritative evidence for the represented scope. Missing, stale, malformed, unavailable, unsupported, or unverified required evidence fails closed.

Wardveil applies least privilege, data minimization, explicit authority, conservative aggregation, and auditable decision/execution separation. Shared evidence must not become a secret store or unrestricted telemetry lake. Unknown inspection results are not clean results, and anomaly alone is not proof of malicious behavior.

High-impact cross-service technical actions require an explicit authorized executor plus a short-lived authorization bound to the exact policy record, action, scope, executor identity, idempotency key, replay nonce, and validity window. Before an authorized high-impact side effect is attempted, the Foundation 0.9 durable execution-state model claims that authorization so an uncertain process failure cannot silently authorize the same mutation again.

## Authority model

Wardveil 0.9 has scoped first-party technical authority for Wardveil-native trust states, policy decisions, protection/enforcement results, detection findings, scan findings, quarantine state, incident workflow state, audit records, and Wardveil security presentation semantics.

This does **not** mean Wardveil automatically becomes authoritative for every underlying control. Applications, infrastructure systems, authentication services, firewalls, scanners, and other producers remain authoritative for their own state until integrated through an explicit Wardveil contract.

A Wardveil Policy decision is also not automatically execution authority. Target systems and approved executors retain their own action/resource authorization requirements.

Branding alone is never evidence of protection or integration.

## Runtime execution authorization

Foundation 0.9 introduces `contracts/wardveil.runtime-authorization.json`, `docs/RUNTIME-AUTHORIZATION.md`, and `reference/wardveil_runtime_authorization.py`.

The reference flow is:

`authoritative evidence -> Trust/Policy -> policy decision -> runtime authorization -> authorized Protect executor -> protection result -> Audit`

The authorization is bound to the exact policy digest, policy record ID, correlation ID, action, target scope, executor ID, idempotency key, nonce, issue time, expiry, and signing-key ID. It cannot outlive its policy decision. Invalid signatures, expired or excessive validity windows, future-dated authorization, policy mutation, action/scope/executor mismatch, unknown/revoked keys, and conflicting nonce reuse fail closed.

The source reference uses `HMAC-SHA256-reference-only` solely for dependency-free contract testing. Production cryptography, key management, rotation/revocation, authenticated transport, durable replay/idempotency storage, and runtime executor evidence remain **unaccepted** until deployed and validated.

## Durable execution state

`docs/EXECUTION-STATE.md`, `contracts/wardveil.execution-state.json`, and `reference/wardveil_execution_state.py` define the next Foundation 0.9 safety layer.

The guarded sequence is:

`verify authorization -> durable claim -> local executor authorization -> execute -> authoritative Protect record -> durable receipt -> Audit/Security Center`

A nonce conflict or executor/idempotency conflict fails closed. An exact retry after a finalized outcome returns the original receipt without invoking the handler again. A claim that exists without a finalized receipt becomes `execution_reconciliation_required`; Wardveil prohibits automatic blind re-execution because the external side effect may already have occurred.

The existing Cloudflare Durable Object persistence adapter exposes the versioned private `wardveil-persistence-rpc/v1` service-binding API for bounded record persistence, checkpoints, execution claims/receipts, maintenance evidence, and health. Its public HTTP boundary is limited to non-mutating `/healthz` liveness and `/readyz` dependency readiness; application mutation remains private service-binding/RPC only. This is deployable source, not proof that durable execution state or the private API is currently deployed or production-accepted.

A durable claim cannot make a non-idempotent external API exactly-once. Every production executor still requires idempotency or an authoritative state-reconciliation mechanism in the system that owns the side effect.

## Service identity and signing keys

`docs/SERVICE-IDENTITY.md`, `contracts/wardveil.service-identity.json`, and `reference/wardveil_service_identity.py` define explicit first-party issuer/executor identities and signing-key lifecycle. Active identities require their declared capability. Suspended, revoked, expired, unknown, or capability-mismatched identities fail closed.

Execution authorization carries a nonsecret signed `signing_key_id`. Active keys may sign, retired keys may verify only through a bounded rotation overlap, and revoked keys fail immediately. Signing material remains outside authorization envelopes, shared security records, durable execution state, application source, and CI logs.

`cloudflare/authorization-issuer/` provides a separate internal Worker source candidate so persistence does not become a signing authority. Its current HMAC mechanism remains reference-only and production runtime acceptance remains unaccepted.

## Quarantine executor transport

`docs/QUARANTINE-EXECUTOR.md`, `contracts/wardveil.quarantine-executor.json`, and `reference/wardveil_quarantine_executor.py` define the first bounded high-impact Protect executor implementation path.

The guarded sequence is:

`identity-bound authorization -> durable claim -> quarantine target -> exact target readback -> Protect receipt -> Quarantine + Audit -> Security Center`

The executor accepts only the `quarantine` action. The target system remains authoritative for actual quarantine state. A successful target call without exact readback does not count as successful quarantine. Target timeout, ambiguous outcome, readback mismatch, or receipt persistence loss after a possible side effect produces `execution_reconciliation_required`; the original authorization cannot be blindly replayed.

Quarantine is not deletion. A successful quarantine record begins in `pending` review state with `destructive_action=false`. Release and removal remain separate explicit authorities.

Audit can hash-bind nonsecret `authorization_id`, `issuer_id`, `executor_id`, `signing_key_id`, and signature-algorithm provenance, and Security Center may surface those fields for investigation. Provenance alone cannot create or upgrade a Protected state.

`cloudflare/quarantine-executor/` is internal-RPC-only source with public fetch fixed to `404`, Workers.dev and preview URLs disabled, a durable persistence service binding, and an explicit `REPLACE_AT_DEPLOYMENT` target-service placeholder. The Worker refuses execution until an authorized target is configured. No production quarantine service is claimed by source alone.

The Cloudflare deployment gate is defined by `.github/workflows/deploy-cloudflare-quarantine-executor.yml` and `contracts/wardveil.quarantine-executor-deployment.json`. A manual production dispatch must identify an already deployed target Worker and an explicit least-privilege resource-type subset. The workflow verifies target and persistence Worker existence, requires the verification secret to be pre-provisioned without reading its value, generates an ephemeral configuration, keeps Workers.dev and preview URLs disabled, deploys the executor, and runs a local-only non-mutating remote service-binding probe. The probe can prove internal executor reachability and that the deployment placeholder was replaced; it cannot prove a quarantine mutation or authorize production acceptance.

## Project governance

The authoritative project requirements and significant project history are repository-local:

- [Documentation index](docs/README.md)
- [Project specifications](docs/PROJECT-SPECIFICATIONS.md)
- [Project record](docs/PROJECT-RECORD.md)

[Features](docs/FEATURES.md) retains durable feature-scope documentation. Current implemented and planned feature state is authoritative in [Implemented features](docs/IMPLEMENTED-FEATURES.md) and [Planned features](docs/PLANNED-FEATURES.md), with repository change history in [Changelogs](docs/CHANGELOGS.md). The active Drive project specification remains migration provenance only until this repository migration is accepted and its source-retirement gate is satisfied.

## Shared contracts and specifications

- `docs/ARCHITECTURE.md` — canonical first-party security architecture and responsibility boundaries.
- `docs/FEATURES.md` — canonical detailed feature specification across Wardveil services, applications, infrastructure, Security Center, evidence, and platform integrations.
- `contracts/wardveil.capabilities.json` — machine-readable capability and lifecycle contract.
- `docs/RUNTIME-AUTHORIZATION.md` and `contracts/wardveil.runtime-authorization.json` — cross-service execution authorization, exact binding, replay, idempotency, and production-acceptance boundary.
- `docs/EXECUTION-STATE.md` and `contracts/wardveil.execution-state.json` — durable authorization claims, uncertain-outcome handling, idempotency state, execution receipts, and deployment boundary.
- `docs/PERSISTENCE.md`, `contracts/wardveil.persistence-production-qualification.schema.json`, and `qualification/persistence-production/` — non-authorizing exact-candidate/deployment persistence qualification for durability, integrity, encryption/key custody, backup/restore, migration/rollback, access control, observability, monitoring, and Everkeep recovery evidence.
- `docs/PLATFORM-API.md` and `contracts/wardveil.platform-api.v1.json` — bounded private `wardveil-persistence-rpc/v1` service-binding API declaration for supported first-party persistence/execution-state integration, with production API acceptance explicitly unaccepted.
- `docs/SERVICE-IDENTITY.md` and `contracts/wardveil.service-identity.json` — service identities, capability binding, signing-key identity, rotation, revocation, and production key-management boundary.
- `docs/QUARANTINE-EXECUTOR.md`, `contracts/wardveil.quarantine-executor.json`, and `contracts/wardveil.quarantine-executor-deployment.json` — bounded high-impact quarantine execution, target idempotency/readback, deployment gating, reconciliation, Audit provenance, and Cloudflare acceptance boundaries.
- `docs/STATUS.md` and `contracts/wardveil.status.schema.json` — evidence-backed Wardveil status semantics.
- `docs/AGGREGATION.md` and `contracts/wardveil.aggregation.vectors.json` — conservative multi-record aggregation.
- `docs/PRIVACY-SHIELD.md` and `contracts/wardveil.privacy-shield.vectors.json` — privacy-safe read-only Privacy Shield presentation boundary.
- `docs/THREAT-MODEL.md` — trust boundaries and misuse cases.
- `docs/ADOPTION.md` — minimum integration and acceptance requirements.
- `docs/CLAMAV-INTEGRATION.md` — replaceable malware-engine, runtime-health, deployment, and acceptance architecture beneath Wardveil Scan.
- `contracts/wardveil.clamav.health.schema.json` — data-minimized ClamAV component-health evidence.
- `contracts/wardveil.clamav.runtime-acceptance.json` — production acceptance requirements for the deployed ClamAV runtime.
- `docs/SECURITY.md` — repository security and sensitive-information boundaries.
- `docs/ICON.md` — canonical visual-identity contract.

The normalized status states remain `protected`, `attention`, `degraded`, `unknown`, and `not_applicable`.

## Platform relationships

- **Privacy Shield** owns privacy-control contracts, tracking resistance, data minimization expectations, and privacy-specific runtime behavior. Wardveil may present sanitized Privacy Shield status but does not inherit Privacy Shield authority.
- **Everkeep** owns resilience, backup, recovery, preservation, portability, succession, and digital-legacy capabilities. Wardveil can coordinate compromise containment and post-recovery verification without taking over Everkeep's recovery authority.
- **GoreeCloud Mesh** is the coordination and governance plane connecting first-party applications and services. Wardveil can use Mesh for authenticated security-signal, decision, and runtime-authorization transport while retaining Wardveil security semantics.
- **Glaze UI** defines the visual and interaction model used by Wardveil Security Center and embedded Wardveil surfaces.

## Application integration

GoreeCloud applications should consume Wardveil first-party security services rather than independently recreating malware scanning, session-risk evaluation, policy decisions, quarantine semantics, incident response, or security audit behavior.

An integration should map authoritative producers, request or consume Wardveil decisions, require bound runtime authorization for supported high-impact cross-service actions, preserve local executor authority, use durable execution state for high-impact cross-service mutation, respect quarantine state, emit security-relevant audit events, exclude prohibited sensitive material, and expose only evidence-backed Wardveil status.

Detailed application scopes for Browser, Mail, Drive, Vault, AI, Messenger, Identity, Search, Gateway, Network, infrastructure, and other authorized services are maintained in `docs/FEATURES.md`.

## Malware protection engine

Wardveil Scan uses ClamAV as its initial replaceable signature-based malware engine through `reference/wardveil_clamav.py`. The adapter streams content to `clamd` using INSTREAM, preserves positive malware signatures as malicious findings, and fails closed on scanner errors or unsupported/incomplete scans. It does not delete or quarantine files; Wardveil Policy, Protect, and Quarantine retain authorized response authority.

`reference/wardveil_clamav_runtime.py` adds runtime-health evidence and a clean-verdict gate. A ClamAV `OK` result remains `clean` only while associated health evidence is healthy, unexpired, daemon-reachable, and backed by current loaded signature data. Stale, unavailable, expired, future-dated, or unverified health downgrades a would-be clean result to `unknown`; positive malware matches remain malicious even when health is degraded.

`deployment/clamav/` provides a loopback-only container baseline, persistent signature database storage, environment-driven limits and freshness policy, and a health collector. `contracts/wardveil.clamav.runtime-acceptance.json` deliberately remains `unaccepted` until deployed runtime tests, application consumers, and authorized quarantine evidence exist.

The product direction is **Wardveil Malware Protection** within Wardveil Security Center, with ClamAV supplying the first signature-based scanning engine and additional first-party or replaceable detection engines added over time. A healthy ClamAV runtime alone does not authorize a broad `Protected by Wardveil` claim.

## Protected by Wardveil

`Protected by Wardveil` may be asserted only for an explicit scope backed by current authoritative evidence showing that a Wardveil control or Wardveil-authorized producer actually enforced or verified the represented protection. A Wardveil icon, a Security Center screen, a ClamAV installation, ClamAV health evidence, a runtime-authorization envelope, a service identity, a signing key, a durable execution-state claim, a quarantine-executor source/deployment candidate, or a Privacy Shield status record does not independently authorize that claim.

## Validation

Run:

```bash
python3 scripts/validate_wardveil.py
python3 scripts/validate_wardveil_capabilities.py
python3 scripts/test_wardveil_runtime_authorization.py
python3 scripts/validate_wardveil_runtime_authorization.py
python3 scripts/test_wardveil_service_identity.py
python3 scripts/validate_wardveil_service_identity.py
python3 scripts/test_wardveil_execution_state.py
python3 scripts/validate_wardveil_execution_state.py
python3 scripts/test_wardveil_persistence_production_qualification.py
python3 scripts/validate_wardveil_persistence_production_qualification.py
python3 scripts/test_wardveil_quarantine_executor.py
python3 scripts/validate_wardveil_quarantine_executor.py
python3 scripts/validate_cloudflare_quarantine_executor.py
python3 scripts/validate_cloudflare_quarantine_executor_deployment.py
python3 scripts/test_wardveil_detect_scan_reference.py
python3 scripts/test_wardveil_clamav.py
python3 scripts/test_wardveil_clamav_runtime.py
python3 scripts/validate_wardveil_clamav_runtime.py
python3 scripts/validate_cloudflare_persistence.py
python3 scripts/validate_wardveil_aggregation.py
python3 scripts/validate_wardveil_privacy_shield.py
```

CI validates the canonical capability set, lifecycle, version alignment, runtime authorization, service identity/key lifecycle, durable execution claims/receipts, the non-authorizing production-persistence qualification boundary, bounded quarantine execution and target-readback semantics, the quarantine deployment gate and non-mutating service-binding probe, Audit/Security Center provenance, evidence boundaries, all Wardveil Cloudflare Worker source candidates, ClamAV protocol/runtime-health/deployment invariants, aggregation, Privacy Shield separation, repository governance, icon state, and public-site tooling against the exact source revision.

## Release discipline

Foundation releases keep `VERSION`, `contracts/wardveil.identity.json`, `contracts/wardveil.capabilities.json`, runtime-authorization, service-identity, execution-state, quarantine-executor/deployment metadata, `docs/CHANGELOG.md`, compatibility metadata, validator expectations, and the README current-status declaration synchronized. Product-specific and runtime-specific production acceptance remains separate from Wardveil foundation acceptance.
