# Wardveil — Delivery Roadmap

| Field | Value |
| --- | --- |
| Document type | Product and engineering roadmap |
| Owner | GoreeCloud |
| Status | Proposed; no phase is accepted or complete |
| Created / updated | 2026-10-25 |
| Canonical location | `GoreeCloud/wardveil/docs/roadmap.md` |

## Delivery strategy

Build an end-to-end security workflow before attempting every technology integration. Keep the seven product names as logical modules in a shared platform; release individual capabilities only after evidence-backed acceptance. Avoid adding large dependency stacks before required ownership, licensing, operational cost and risk are understood.

| Phase | Primary deliverable | Example acceptance evidence |
| --- | --- | --- |
| **0 — Foundations** | Repository structure, GC UI integration plan, threat model, architecture decisions, CI checks, contracts, test fixtures | Reproducible builds, lint/tests, documented trust boundaries and rollback |
| **1 — Scan MVP** | Authenticated scan jobs; isolated ClamAV file scanning; source-product quarantine contract; findings, incidents and audit events | Benign/EICAR test fixtures in isolated environment, bounded archive tests, authorized upload hold/release, accurate verdict/error states |
| **2 — Visibility** | Wardveil Security case views, alerts and search; Sentinel event adapters and Intel enrichment in read-only mode | Ingest/correlation tests, redaction tests, event provenance and provider outage handling |
| **3 — Posture and defense** | Trivy vulnerability jobs; Shield observe-only policies, WAF/CrowdSec integration test adapters | Reproducible finding results, staged rule evaluations, no unapproved traffic blocking |
| **4 — Safe response** | Policy engine, Class A automation and narrowly scoped reversible Class B workflows | Authorization, idempotency, audit, expiry, rollback, false-positive and failure-mode tests |
| **5 — Assurance and expansion** | Wardveil Trust, organization scoping, retention/evidence, native clients or services for declared OS targets | Tenant-isolation validation, provenance-backed reports, OS-specific build/install/runtime evidence |
| **6 — External platform readiness** | Tenant administration, supported APIs/SDKs, operational hardening, licensing and billing decisions if approved | Isolation, disaster recovery, documented SLAs/limitations, privacy and security acceptance |

Phase numbers indicate dependency order, **not** deadlines, maturity, or deployment state.

## First implementation milestone: working file-scan loop

Build a single secured path from a GoreeCloud upload to a verifiable security finding:

1. Define `ScanRequested`, `ScanVerdict`, `FindingCreated` and `ActionProposed` contracts.
2. Add a file-owning service's pending/quarantine lifecycle contract; never give Wardveil arbitrary filesystem authority.
3. Isolate the ClamAV worker behind a scanner interface, including signature/database readiness checks.
4. Add asynchronous job and status handling, idempotency, backpressure and bounded retries.
5. Persist normalized findings and an immutable-action-trace design, with retention controls.
6. Show job status, alerts and evidence in a GC UI-aligned command-center view.
7. Exercise benign, known-safe test indicator, malformed file, engine-down, scanner-timeout and duplicate-request cases.
8. Release only to a controlled environment after signed-off implementation evidence; do not claim native OS support without native artifacts and runtime verification.

## Follow-on provider integration sequence

- **YARA**: curated, signed or otherwise provenance-verified rules after ClamAV worker safety.
- **Trivy**: container/repository/image vulnerability jobs as a distinct workflow from end-user antivirus.
- **Wazuh/Suricata**: prioritized telemetry intake and detection tuning; instrument only authorized devices/networks.
- **CISA KEV, URLhaus and other intelligence**: normalization, TTL, source confidence and privacy-respecting lookup policies; use a feed only after verifying its terms.
- **CrowdSec, OWASP CRS and Cloudflare WAF**: shadow/observe mode first, followed by scoped and reversible enforcement.
- **Vault and Identity**: mocked contracts first; later invoke product-owned protective APIs only through approved, least-privilege, auditable flows.
- **Wardveil Trust**: evidence-backed reporting once trustworthy, retained, access-controlled events exist.

## Backlog themes

1. **Control plane:** event schemas, incident lifecycle, asset inventory, policy evaluation, multi-tenant preparation.
2. **Scanning:** adapter contracts, worker isolation, quarantine handshakes, resurveys, signature freshness.
3. **Detection:** correlation rules, alert quality, provenance, false-positive handling.
4. **Enforcement:** dry-run, scopes, action limits, approval, expiry, reversible adapters.
5. **Operations:** observability, service health, migrations, backups/restore, supply chain, CI and platform release gates.
6. **Experience:** GC UI compliance, accessible triage, native app requirements, onboarding and explanation of permissions.
7. **Trust:** retention, evidence, transparency, tenant isolation and accurately scoped compliance assessments.

## Release gates

A phase is only accepted once its implementation is verified at the appropriate level: source tests, integration tests, abuse-case tests, authorized runtime checks, documented limitations, and recovery evidence. A passed CI workflow does not automatically prove production or Stable readiness.

For work remaining beyond a session, register concrete obligations in the **currently authoritative GoreeCloud task system** under the governing task-migration procedure. GitHub issues may track repo-native engineering work, but are not a substitute for the canonical cross-product task registry.

## Explicit non-goals for the MVP

- No universal SIEM replacement on day one.
- No unrestricted automatic credential rotation, mass session termination, blanket network blocklists, or raw-file uploads to public reputation services.
- No claims of compliance certification or supported native OS targets without verified evidence.
- No reimplementation of Vault secret storage or Identity authentication.
