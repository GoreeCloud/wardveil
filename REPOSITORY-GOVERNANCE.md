# Wardveil Security Repository Governance

Wardveil Security is GoreeCloud's platform-wide security identity and presentation authority. Its repository governance must therefore preserve a reviewable, fail-closed path from proposed source to accepted source.

## Required source-controlled controls

The repository must retain:

- exact-revision continuous integration on pull requests;
- an explicit CI runner release rather than the moving `ubuntu-latest` label;
- read-only workflow permissions unless a narrowly documented write is required;
- `persist-credentials: false` for source checkout;
- immutable commit-SHA references for third-party GitHub Actions used by the validation workflow;
- automated update discovery for pinned GitHub Actions without automatic production deployment;
- a security reporting policy that prohibits credentials, secrets, raw private security evidence, and unrestricted operational exports;
- deterministic validation for Wardveil identity, status, aggregation, Privacy Shield interoperability, canonical visual identity, and public-site source.

## Required GitHub repository setting

The default `main` branch must be protected by GitHub branch protection or an equivalent repository ruleset before repository governance can be considered fully enforced.

The protection should, at minimum:

- require changes to reach `main` through a pull request;
- require the Wardveil validation workflow to pass before merge;
- prevent required checks from being bypassed as part of ordinary development;
- prevent force-push and branch deletion of `main` unless a documented emergency recovery procedure explicitly requires it;
- preserve administrator review of security-sensitive changes rather than enabling unattended dependency deployment.

Where the available GitHub plan or repository capabilities prevent a specific control, the gap must be recorded explicitly rather than represented as enforced.

## Current verified external-setting state

As verified on August 20, 2026, GitHub reports `main` as unprotected, with branch-level required status-check enforcement disabled. This is an external repository-setting gap, not a source-validation failure.

GitHub Issue #34, **Protect main and require Wardveil validation**, tracks remediation and defines the acceptance evidence required before this control may be recorded as enforced.

Source-controlled CI, immutable Action pins, explicit runner selection, Dependabot update discovery, CODEOWNERS routing, and Wardveil validators reduce risk while this external setting remains unresolved, but they do not substitute for branch protection.

## Dependency automation boundary

Dependabot may discover and propose GitHub Actions updates. Dependabot proposals remain subject to the same review and validation requirements as other source changes. Dependency automation must not merge or deploy changes merely because an upstream release exists.

Every governed GitHub Action reference in the validation workflow must use a full immutable commit SHA and include an adjacent semantic-version annotation for reviewability. Repository validation verifies that the reference is structurally immutable and explicitly version-annotated; it does not hard-code the current commit value, because doing so would make a legitimate pin-update pull request fail solely for changing the pin it is intended to maintain.

Human review remains responsible for evaluating a proposed upstream Action revision, its release notes, compatibility, security implications, and whether the pinned commit corresponds to the intended upstream release before merge. A passing repository-governance check proves pin immutability and repository-policy conformance, not independent upstream trustworthiness.

## Acceptance rule

A Wardveil source revision may pass repository validation while the external branch-protection gap remains open. Such validation proves the revision's source-controlled contracts and tests; it does not prove that GitHub repository governance is fully enforced.
