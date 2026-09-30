# Wardveil Security — User Manual

## About Wardveil Security

Wardveil Security is GoreeCloud’s platform-wide security system for trust, policy, protection, detection, scanning, quarantine, response, audit, and security evidence.

Wardveil is currently in **Development**. This manual documents the supported user- and administrator-facing behavior that can be described from the current repository without treating planned Wardveil 2.0 capabilities as already deployed.

## Intended Audience

This manual is for:

- GoreeCloud administrators reviewing Wardveil state and evidence;
- users viewing Wardveil-backed security information in supported GoreeCloud applications;
- maintainers validating Wardveil integrations and Security Center behavior.

Wardveil does not currently provide one universally production-accepted standalone experience across every GoreeCloud product. Each integration retains its own acceptance boundary.

## Core Concepts

### Security state is evidence-backed

Wardveil security state must be supported by current authoritative evidence. Missing, stale, malformed, unsupported, conflicting, or unverified evidence must not be presented as clean or protected.

### Protection coverage is separate from security state

A component can have a known security state without having complete protection coverage. Security Center and consumer applications must keep gaps visible.

### Trust is not authorization

Wardveil Trust may inform a security decision, but it does not grant access to a target resource. Target systems retain their own authorization requirements.

### Policy decisions are not execution receipts

A Policy decision or Wardveil runtime authorization does not prove that an external action completed. Where Wardveil coordinates a target action, authoritative target-state readback or an equivalent verified receipt is required.

### Quarantine is not deletion

Quarantine means non-destructive isolation or held state. Release, restore, remove, delete, or other mutations are separate actions with their own authorization and verification requirements.

## Security Center

Security Center is Wardveil’s primary user and administrative surface.

Security Center source/build migration to the current Glaze UI 1.6.0 Stable target is integrated through PR #150. Security Center remains acceptance-required until human rendered review, representative accessibility/performance, rollback, deployed-byte/provenance, consumer-registry, deployment, live-evidence, runtime, and production gates are complete.

Until that migration and live evidence acceptance are complete:

- do not interpret the interface as proof of production protection;
- treat status as bounded to the evidence and runtime identified by the surface;
- do not infer platform-wide coverage from one consumer or one passing check.

## Understanding Wardveil Status

When a Wardveil-enabled surface presents security information, review:

1. **Scope** — the application, service, device, account, file, session, or other object represented.
2. **Capability** — what protection or security function is being described.
3. **State** — the current bounded result.
4. **Evidence source** — the authoritative producer or verifier.
5. **Freshness** — when the evidence was observed and whether it is still within its accepted validity window.
6. **Coverage** — whether the applicable enforcement or monitoring path is actually present.
7. **Limitations or blockers** — missing integrations, unavailable evidence, reconciliation requirements, or other conditions preventing a positive claim.

A favorable label without current evidence is not a valid Wardveil protection claim.

## Wardveil Scan

Wardveil Scan provides a shared inspection boundary for supported content. The current implementation uses ClamAV as a replaceable malware-scanning engine beneath Wardveil.

For supported consumers:

- a malicious result may be used as security evidence for a bounded action;
- a clean result is valid only when required engine/signature/evidence conditions are satisfied;
- an unknown, failed, unsupported, stale-signature, or malformed result must not be treated as clean;
- Scan results do not independently grant permission to delete, quarantine, release, or otherwise mutate a resource.

Do not bypass a failed or unknown scan by manually relabeling it clean.

## Incidents, Quarantine, and Response

Current Development contracts distinguish:

- security events and findings;
- incidents that group related evidence;
- containment/protection actions;
- quarantine state;
- recovery coordination;
- verified execution outcomes;
- unresolved execution reconciliation.

When an action may have occurred but Wardveil cannot prove the final target state, the correct state is reconciliation required. Do not blindly repeat high-impact actions.

## Identity and Credentials

GoreeCloud Identity remains authoritative for production service identity, credential issuance, JWKS trust, and key custody.

Do not place reusable credentials, private keys, signing material, recovery codes, tokens, or secret-bearing operational exports in Wardveil repository files, ordinary evidence, support bundles, issues, or pull requests.

Reference HMAC mechanisms in source are for Development contract testing and are not approved production cryptography.

## Privacy

Privacy Shield remains authoritative for privacy and data-use decisions.

Wardveil may use or produce security evidence relevant to privacy decisions, but it must minimize shared evidence and avoid exposing raw private content when a bounded derived result is sufficient.

## Recovery

Everkeep remains the GoreeCloud recovery authority.

A backup is not enough to claim Wardveil recovery readiness. Restored Wardveil state must preserve the security properties required by the affected capability, such as replay protection, execution reconciliation, policy identity, incident/quarantine state, and audit provenance.

Security-sensitive restored systems should be reverified before normal operation resumes.

## Troubleshooting

### A surface shows unknown, blocked, stale, or migration required

This is a fail-closed condition, not automatically a product failure. Review the evidence source, freshness, declared integration state, runtime acceptance, and current platform-system blockers.

Do not change the displayed state to Protected solely to remove a warning.

### A Scan result is unknown

Confirm that the scanning engine is reachable and that required signature/evidence freshness conditions are satisfied. If the authoritative result remains unknown, keep it unknown and follow the consumer’s safe failure behavior.

### An action shows reconciliation required

Do not retry the action blindly. Determine the authoritative target state first, then reconcile Wardveil’s execution record with the actual result.

### Security Center looks complete but production acceptance is unavailable

Presentation is not authority. Check the exact consumer/runtime evidence and current lifecycle state. Wardveil remains Development until its applicable production gates are separately satisfied.

## Reporting Security Problems

Do not publish active secrets, exploit-sensitive infrastructure details, private user content, or unrestricted operational evidence in public issues.

Use the approved private GoreeCloud administrative or repository security-reporting path. Sanitize any information that can safely be discussed in an ordinary issue or pull request.

## Current Limitations

Current major limitations include:

- no platform-wide production acceptance;
- production Identity/key custody and approved cryptography remain incomplete;
- target execution/readback remains capability-specific and incomplete;
- Privacy Shield, Everkeep, GoreeCloud Policy, and GoreeCloud Observability acceptance remain incomplete where applicable;
- Security Center’s Glaze UI 1.6 source migration is integrated, while exact rendered/accessibility/performance, rollback, deployed-byte/provenance, consumer-registry, deployment, live-evidence, runtime, and production acceptance remain open;
- persistent Wardveil 2.0 engines and broad adaptive-security behavior remain planned/Development work;
- release and Stable qualification remain open.

## Related Repository Documentation

- `README.md` — repository overview and current architecture.
- `CAPABILITIES.md` — current capability state.
- `SPECIFICATIONS.md` — repository requirements and boundaries.
- `FEATURES.md` — feature scope.
- `FEATURE-ROADMAP.md` — planned and ongoing feature work.
- `SECURITY.md` — repository security handling requirements.
- `BRANDING.md` — Wardveil identity authority and derivative rules.

When documentation and live authoritative evidence disagree, verify the system that owns the fact and use the narrower evidence-backed claim until the discrepancy is resolved.
