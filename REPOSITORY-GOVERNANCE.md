# Wardveil Security Repository Governance

Wardveil Security is GoreeCloud's platform-wide security identity and presentation authority. Its repository governance must preserve a reviewable, fail-closed path from proposed source to accepted source.

## Required source-controlled controls

The repository must retain:

- an exact-revision validation workflow with least-privilege permissions;
- immutable GitHub Action pins with adjacent release annotations;
- CODEOWNERS routing for governed source and policy surfaces;
- bounded dependency automation;
- a pull-request template that records validation, security, authority, and rollback boundaries;
- a security reporting policy that keeps protected information out of public issue and source surfaces;
- deterministic validation for Wardveil identity, status, aggregation, Privacy Shield interoperability, repository governance, branding, and public-site source.
- a first-party retained-public-history audit that fetches retained public branch and tag heads, scans reachable Git blobs for credential-shaped secrets, suppresses matched values from logs, and fails closed on findings or skipped oversized blobs. Untrusted external pull-request refs are excluded from the required check so an outside contributor cannot deny service to protected-branch CI by injecting a detector-shaped fixture.

## Required GitHub repository setting

The default `main` branch must be protected by GitHub branch protection or an equivalent repository ruleset before repository governance can be considered fully enforced.

The required control objectives are:

- material changes reach `main` through pull requests;
- `Validate Wardveil foundation` is required and strict/up-to-date before merge;
- at least one approving review is required;
- stale approvals are dismissed after material changes;
- the last push requires approval;
- review conversations must be resolved;
- administrator enforcement is enabled;
- force pushes are disabled;
- branch deletion is disabled.

A provider limitation must be documented rather than represented as equivalent enforcement. Protection must not be weakened merely to merge a failing or unreviewed change.

## Public repository safety boundary

Wardveil is intentionally public by owner decision. Public visibility is acceptable only while unrestricted disclosure remains safe.

The public repository must not contain:

- active authentication or recovery material;
- private GoreeCloud repository inventory;
- restricted operational evidence or provider-selection internals that belong to a non-public authority;
- raw private activity, private identifiers, or protected telemetry;
- non-public infrastructure detail whose disclosure would materially weaken security.

References to GitHub Actions secret names, safe placeholders, public repository identities, public contracts, public documentation, and deliberately sanitized security architecture are permitted when no protected value is disclosed.

Public interoperability records must use minimized, allowlisted fields. Repository validation must fail closed if restricted producer provenance is reintroduced into a governed public record.

## Current verified external-setting state

As verified on September 27, 2026, GitHub reports `main` as protected and the Wardveil repository as public.

Branch metadata reports `Validate Wardveil foundation` as a required check enforced for everyone. Owner-side protection readback additionally verified strict/up-to-date checks, one required approval, stale-review dismissal, last-push approval, conversation resolution, administrator enforcement, and disabled force pushes and branch deletion.

The September 27 public-safety audit found over-detailed cross-repository Privacy Shield provenance in the interoperability documentation and evidence record: exact repository/source revisions and tree/blob identities, validation-run identifiers, provider-candidate records, and evidence/review paths that Wardveil does not need for public presentation. Privacy Shield's GitHub repository is currently public, so this is a data-minimization and authority-boundary finding rather than exposure of a currently private repository identity. The current governance-hardening candidate removes that detail from its tip and adds fail-closed validation to keep the Wardveil record minimized.

This current-source remediation does **not** rewrite historical commits or stale branch tips. Any history sanitization is a separate controlled operation and must not be represented as completed by a normal forward commit.

The foundation workflow also performs a first-party retained-public-history credential scan. The scanner is a detection control, not historical erasure: a passing scan means the fetched retained refs contained no recognized credential-shaped secret under the enforced detector set; it does not make previously published restricted non-secret provenance disappear.

## Planned GoreeCloud Code transition

GoreeCloud Code is planned as a public-facing repository-hosting service that supports both public and access-controlled private repositories. Wardveil Security and GoreeCloud Privacy Shield are planned to be private repositories in GoreeCloud Code.

That is planned state, not current implementation. Until a governed migration is completed and authoritatively verified, GitHub remains the current source-control authority for these repositories and Wardveil's current GitHub public-safety controls remain in force. A future migration must preserve exact history and revision identity, access controls, branch protection/review requirements, integrations, and recovery while verifying the resulting private repository boundary.

## Dependency automation boundary

Dependabot may propose bounded GitHub Actions updates, but automation does not approve or merge them.

Every governed Action reference used by the validation workflow must use a full immutable commit SHA and include an adjacent semantic-version annotation. Human review remains responsible for evaluating upstream changes, release notes, compatibility, and security implications before merge.

Automated validation proves the checks it actually executes; it does not establish independent upstream trust, deployment acceptance, production authority, or Stable status.

## Acceptance rule

A Wardveil candidate is merge-eligible only when:

1. the exact current head is known;
2. applicable checks pass on that exact head;
3. the target branch's protection requirements are satisfied;
4. required review is present and still valid;
5. blocking conversations are resolved;
6. rollback remains available;
7. public-source safety controls pass;
8. the merge result is verified on the intended target.

A green workflow on an obsolete head, a successful API response, or a source-only validation result is not sufficient evidence of completion.
