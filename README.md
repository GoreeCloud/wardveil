# Wardveil Security by GoreeCloud

Wardveil Security is GoreeCloud's platform-wide security and protection identity and shared security-state interoperability layer.

It provides a consistent way to identify and present security posture, protection state, warnings, recommendations, audit information, and security-focused experiences across GoreeCloud without replacing the technical systems that produce or enforce that state.

> **Current status:** Foundation 0.7 active. The canonical Wardveil Security icon is approved and stored at `branding/wardveil-security-icon.svg`. The public Wardveil site is implemented, and the Privacy Shield status-presentation boundary is now a versioned shared contract. Runtime adoption and evidence remain product-specific and must pass their own acceptance boundaries.

## Core boundary

Wardveil is an identity, status-contract, aggregation, and presentation layer. Authentication systems, authorization controls, firewalls, private networking, application security controls, vulnerability management, backup and recovery systems, Privacy Shield runtimes, and other authoritative controls remain responsible for their own technical state.

Wardveil must never turn missing evidence into reassurance, broaden a producer's authority, become a secret store, create an unaudited cross-platform remediation channel, or convert a separate GoreeCloud capability into Wardveil-owned protection merely because its status is visible in a Wardveil surface.

## Approved naming

- **Wardveil Security by GoreeCloud** — full attributed presentation
- **Wardveil Security** — primary product and technology name
- **Wardveil** — approved short name
- **Protected by Wardveil** — approved evidence-scoped protection-status phrase

Reserved concepts such as Wardveil Access, Wardveil Network, Wardveil Integrity, Wardveil Threats, Wardveil Verify, Wardveil Watch, and Wardveil Security Center are not approved module or product names.

## Relationship model

- **Glaze UI** defines how GoreeCloud looks, feels, adapts, and interacts.
- **Wardveil Security** defines how GoreeCloud identifies and presents platform-wide security and protection.
- **GoreeCloud Privacy Shield** is the separate platform-wide privacy, privacy-control, tracking-resistance, and data-minimization identity and shared privacy foundation.

Wardveil-facing interfaces use Glaze UI. Wardveil may present sanitized Privacy Shield status in broader protection views, but Privacy Shield retains its own name, icon, privacy authority, capabilities, runtime producers, and acceptance boundaries. Wardveil does not become a Privacy Shield enforcement runtime.

## Shared contracts

- `STATUS.md` defines the Wardveil security-status semantics.
- `contracts/wardveil.status.schema.json` defines the machine-readable Wardveil status structure.
- `AGGREGATION.md` defines conservative multi-record Wardveil presentation aggregation.
- `PRIVACY-SHIELD.md` defines the read-only Privacy Shield status consumer boundary and conservative state mapping.
- `contracts/wardveil.privacy-shield.vectors.json` defines fail-closed Privacy Shield interoperability conformance cases.
- `THREAT-MODEL.md` defines trust boundaries, misuse cases, aggregation safety, and the remediation boundary.
- `ADOPTION.md` defines the minimum integration and acceptance requirements for GoreeCloud consumers.
- `SECURITY.md` defines repository security and sensitive-information boundaries.
- `ICON.md` defines the canonical visual-identity contract and showcase gate.

The normalized Wardveil states are `protected`, `attention`, `degraded`, `unknown`, and `not_applicable`. Missing, stale, unavailable, incomplete, or unverified required evidence must never be promoted to a passing state.

**Protected by Wardveil** may be asserted only for the explicit scope of a Wardveil record backed by current authoritative evidence. Wardveil branding itself is never evidence that a control succeeded. A Privacy Shield record never independently authorizes this claim; Privacy Shield remains the privacy authority for its own protection state.

## Security architecture principles

Wardveil integrations are read-only by default. Each record must preserve authoritative-source identity, explicit scope, observation time, and freshness meaning. Shared evidence is data-minimized and must not contain reusable secrets, active credentials, private keys, tokens, recovery material, unrestricted diagnostics, or unnecessary personal data.

Aggregated Wardveil security views must be conservative: a summary cannot be more favorable than the weakest required evidence in its represented scope. Required `unknown` evidence blocks `protected`.

Privacy Shield status is excluded from Wardveil's primary required-control protection aggregation by default. It may be displayed as contextual information, but availability alone does not authorize aggregation and Privacy Shield protection does not become Wardveil protection.

Wardveil 0.7 does not define a generic remediation API. Applications may link to their own authorized remediation workflows, but technical mutation remains owned and audited by the authoritative system.

## Icon and visual identity

Wardveil Security uses the approved canonical icon at `branding/wardveil-security-icon.svg`. Derived visual assets must remain traceable to that source and follow the canonical identity rules in `ICON.md` and `IDENTITY.md`.

The Wardveil mark uses layered veil geometry around a protected central core. It remains visually and semantically distinct from the canonical GoreeCloud Privacy Shield identity.

## Validation

Run:

```bash
python3 scripts/validate_wardveil.py
python3 scripts/validate_wardveil_aggregation.py
python3 scripts/validate_wardveil_privacy_shield.py
```

The validators check canonical naming, authority boundaries, icon/showcase state, status-contract invariants, protection-claim fail-closed behavior, conservative aggregation, Privacy Shield presentation separation, repository secret exclusions, and required documentation. Canonical SVG validation is separately enforced by `scripts/validate_wardveil_icon.py`.

## Adoption

A GoreeCloud project must not claim Wardveil integration based on branding alone. Adoption requires authoritative-source mapping, protected/non-passing/stale-evidence tests, sensitive-field exclusion, accessible state presentation, and exact-revision CI evidence as defined in `ADOPTION.md`.

Privacy Shield presentation additionally requires the privacy-safe producer guarantees and authority separation defined in `PRIVACY-SHIELD.md`. Wardveil must reject unsafe or ambiguous Privacy Shield status rather than partially interpreting it.

## Release discipline

Foundation releases must keep `VERSION`, `contracts/wardveil.identity.json`, `CHANGELOG.md`, compatibility metadata, validator expectations, and the README current-status declaration synchronized. Material shared-contract additions are release changes, not undocumented post-release drift.

Product-specific runtime acceptance is deliberately separate from Wardveil foundation release acceptance. A passing Wardveil foundation does not make a consuming application production-approved.

## Original identity and optional future due diligence

Wardveil Security is documented here as an original GoreeCloud identity. This project record is not a trademark registration or a legal guarantee of exclusivity in every jurisdiction. Formal name or trademark due diligence may be performed later if expanded public or commercial use makes it useful; it is not a current GoreeCloud engineering blocker.
