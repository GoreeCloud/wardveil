# Wardveil — Proposed Security and Trust Model

| Field | Value |
| --- | --- |
| Document type | Threat-model and security requirements proposal |
| Owner | GoreeCloud |
| Status | Proposed; controls not yet implementation-verified |
| Created / updated | 2026-10-25 |
| Canonical location | `GoreeCloud/wardveil/docs/security-model.md` |

## Protection goals

Protect GoreeCloud services, user content, administrator control, security evidence, and automation integrity while preserving privacy, availability, recoverability, and operational independence. Wardveil itself is a high-value target: compromise of the security control plane must **not** grant blanket access to Vault credentials, Identity accounts, source files, or edge enforcement.

## Threat boundaries

1. **Untrusted files:** Uploaded files, archives, document previews, rules and signatures may contain malicious or adversarial content.
2. **Untrusted telemetry:** Logs, headers, URLs, user-agent strings and provider payloads may contain secrets, forged events, or prompt-injection-like instructions.
3. **External enrichment:** Indicators, reputation scores and third-party results may be stale, maliciously influenced, or expose sensitive lookup metadata.
4. **Security operators:** Privileged users or compromised sessions may alter detections, suppress alerts, issue broad blocks, or erase evidence.
5. **Automation and adapters:** A malformed policy or hijacked provider integration may amplify a false positive into an outage.
6. **Tenant and service boundaries:** One organization/service must never see or act on another organization's protected objects.
7. **Supply chain:** Compromised scanning engines, signatures, rules, CI pipelines, native agents, and updates may undermine defenses.

## Mandatory design safeguards

| Risk | Proposed baseline control |
| --- | --- |
| Malware execution during scan | Isolate workers; never execute samples intentionally; sandbox/archive/resource/time limits; nonprivileged worker identities |
| Sensitive file exposure | Source-owner controlled temporary access; encryption; minimized copies; strict retention and deletion of temporary samples |
| Adversarial provider events | Signed/authenticated ingestion, schema validation, source attribution, replay protection, bounded payloads |
| Inaccurate verdict / false positive | Multi-signal confidence and provenance; manual appeal/review; time-limited holds and exceptions |
| Excessive blocked traffic | Scope limits, dry-run, approval or staged policy rollout, expiry, rollback and independent enforcement readback |
| Compromised control plane | Role separation, MFA enforced through GoreeCloud Identity, privileged action auditing, no universal admin API tokens |
| Credential misuse | Credentials remain under GoreeCloud Vault; service-specific least-privilege short-lived access where supported |
| Cross-tenant exposure | Verified tenant claims and row/object-level authorization on every service boundary, including queues and evidence |
| Evidence tampering | Append-only audit design, actor/time/version attribution, tamper-evidence and restricted retention operations |
| Provider dependency loss | Explicit degraded modes, retries, circuit breakers and operator-visible fail-open/fail-closed decisions |
| Sensitive analytics | Redact before storage; restrict exports and external queries; documented retention, deletion and access trails |
| Malicious rule or signature updates | Trusted provenance, staged rollout, validation, rollback, pinning where necessary |

## Response safety classes

- **Class A — Observational:** Enrich, annotate, alert, and create a case. Can be automatic when authorized.
- **Class B — Reversible scoped mitigation:** Temporarily block a single scoped IP, hold a specific file, or narrow a resource permission. Requires established policy, scope limits, expiry, audit, health checks, and rollback.
- **Class C — High-impact action:** Revoke sessions broadly, disrupt services, rotate critical credentials, delete data, block a network range, or change global WAF rules. Requires explicit elevated authorization and strong verification appropriate to impact.

The response engine proposes actions. Destination system APIs enforce their own authorization and own the final operation. No security score alone authorizes Class C actions.

## Privacy and evidence

- Prefer local analysis; only query third parties with data approved for sharing.
- Treat IPs, hashes, domains, logs and evidence as potentially personal or sensitive.
- Separate operational logging, incident evidence, and report-ready redacted summaries.
- Define data classification, maximum retention, legal hold, export controls, and access requests before collecting production data.
- Never store or expose raw passwords, API keys, recovery codes, private keys, or unnecessary authentication artifacts.
- Trust dashboards may publish only approved, evidence-backed claims; compliance readiness is not equivalent to certification.

## Validation obligations before production

- Threat-model walkthrough of ingress, scanning isolation, authorization, tenant boundaries, API abuse, supply chain and response callbacks.
- Automated negative tests for unauthorized cross-tenant reads/actions, forged events, replay, path traversal, archive bombs, malicious rules, and credential leakage.
- Fault injection of scanner outage, indicator staleness, queue backlog, duplicate messages, WAF provider failure and restoration.
- Dry-run and rollback tests for every response adapter against authorized nonproduction infrastructure.
- Onboarding and UI verification per supported native target OS, following GC UI.
- Backup restore, retention enforcement, audit integrity, revocation, key rotation and staged upgrade tests.

All listed safeguards are **requirements for future work**, not claims that current Wardveil provides them.
