# Wardveil Security by GoreeCloud

Wardveil Security is GoreeCloud's platform-wide first-party security system and shared security plane. It coordinates evidence-backed trust, policy, protection, detection, scanning, quarantine, incident response, audit, and security-center experiences across GoreeCloud.

> **Current status:** Foundation 0.8 active. Wardveil now has a canonical first-party capability architecture and machine-readable capability contract while preserving the existing fail-closed evidence, conservative aggregation, Privacy Shield separation, and product-specific acceptance boundaries.

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

These are substantive first-party security capabilities, not decorative labels. Their canonical responsibility and authority boundaries are defined in `ARCHITECTURE.md` and `contracts/wardveil.capabilities.json`.

## Security lifecycle

A representative lifecycle is:

`Trust -> Policy -> Protect -> Detect -> Scan -> Quarantine -> Response -> Audit`

The lifecycle is not strictly linear. Components may invoke or inform one another as evidence changes. Wardveil Security Center spans the lifecycle as the human-facing visibility and control layer.

## Core security invariants

Wardveil follows evidence before reassurance. Protected state requires current authoritative evidence for the represented scope. Missing, stale, malformed, unavailable, unsupported, or unverified required evidence fails closed.

Wardveil applies least privilege, data minimization, explicit authority, conservative aggregation, and auditable decision/execution separation. Shared evidence must not become a secret store or unrestricted telemetry lake. Unknown inspection results are not clean results, and anomaly alone is not proof of malicious behavior.

High-impact technical actions require an explicit authorized executor, scoped target, validity window, replay resistance where relevant, and audit evidence.

## Authority model

Wardveil 0.8 has scoped first-party technical authority for Wardveil-native trust states, policy decisions, protection/enforcement results, detection findings, scan findings, quarantine state, incident workflow state, audit records, and Wardveil security presentation semantics.

This does **not** mean Wardveil automatically becomes authoritative for every underlying control. Applications, infrastructure systems, authentication services, firewalls, scanners, and other producers remain authoritative for their own state until integrated through an explicit Wardveil contract.

Branding alone is never evidence of protection or integration.

## Shared contracts

- `ARCHITECTURE.md` — canonical first-party security architecture and responsibility boundaries.
- `contracts/wardveil.capabilities.json` — machine-readable capability and lifecycle contract.
- `STATUS.md` and `contracts/wardveil.status.schema.json` — evidence-backed Wardveil status semantics.
- `AGGREGATION.md` and `contracts/wardveil.aggregation.vectors.json` — conservative multi-record aggregation.
- `PRIVACY-SHIELD.md` and `contracts/wardveil.privacy-shield.vectors.json` — privacy-safe read-only Privacy Shield presentation boundary.
- `THREAT-MODEL.md` — trust boundaries and misuse cases.
- `ADOPTION.md` — minimum integration and acceptance requirements.
- `SECURITY.md` — repository security and sensitive-information boundaries.
- `ICON.md` — canonical visual-identity contract.

The normalized status states remain `protected`, `attention`, `degraded`, `unknown`, and `not_applicable`.

## Platform relationships

- **Privacy Shield** owns privacy-control contracts, tracking resistance, data minimization expectations, and privacy-specific runtime behavior. Wardveil may present sanitized Privacy Shield status but does not inherit Privacy Shield authority.
- **Everkeep** owns resilience, backup, recovery, preservation, portability, succession, and digital-legacy capabilities. Wardveil can coordinate compromise containment and post-recovery verification without taking over Everkeep's recovery authority.
- **GoreeCloud Mesh** is the coordination and governance plane connecting first-party applications and services. Wardveil can use Mesh for authenticated security-signal and decision transport while retaining Wardveil security semantics.
- **Glaze UI** defines the visual and interaction model used by Wardveil Security Center and embedded Wardveil surfaces.

## Application integration

GoreeCloud applications should consume Wardveil first-party security services rather than independently recreating malware scanning, session-risk evaluation, policy decisions, quarantine semantics, incident response, or security audit behavior.

An integration should map authoritative producers, request or consume Wardveil decisions, honor supported enforcement actions, respect quarantine state, emit security-relevant audit events, exclude prohibited sensitive material, and expose only evidence-backed Wardveil status.

## Protected by Wardveil

`Protected by Wardveil` may be asserted only for an explicit scope backed by current authoritative evidence showing that a Wardveil control or Wardveil-authorized producer actually enforced or verified the represented protection. A Wardveil icon, a Security Center screen, or a Privacy Shield status record does not independently authorize that claim.

## Validation

Run:

```bash
python3 scripts/validate_wardveil.py
python3 scripts/validate_wardveil_capabilities.py
python3 scripts/validate_wardveil_aggregation.py
python3 scripts/validate_wardveil_privacy_shield.py
```

CI validates the canonical capability set, lifecycle, version alignment, evidence boundaries, aggregation behavior, Privacy Shield separation, repository governance, icon state, and public-site tooling against the exact source revision.

## Release discipline

Foundation releases keep `VERSION`, `contracts/wardveil.identity.json`, `contracts/wardveil.capabilities.json`, `CHANGELOG.md`, compatibility metadata, validator expectations, and the README current-status declaration synchronized. Product-specific runtime acceptance remains separate from Wardveil foundation acceptance.
