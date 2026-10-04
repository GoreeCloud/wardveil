# Wardveil Security — Version 2.0 Release Provenance and Rollback Evidence

**Requirement level:** Mandatory  
**Status:** Template defined; evidence not yet accepted  
**Candidate:** `wardveil-2.0.0-seal.1`

## Purpose

This record defines the evidence that must exist before the Version 2.0 `release-provenance-rollback` Anchor gate can pass. The machine-readable template is `qualification/release-evidence.template.json`.

The template is deliberately non-authorizing. It records required evidence shape while every release-specific field remains pending or null.

## Required final evidence

A final accepted record must bind one exact Version 2.0 release to:

- the governed candidate source and exact published release/tag identity;
- artifact name, package identity, and SHA-256 digest;
- required SBOM identity and digest;
- required signing/provenance identity and digest;
- source/build attestation where applicable;
- exact deployed revision/environment identity and observation time;
- an accepted rollback target, rollback artifact identity, and a completed rollback exercise;
- canonical post-release readback and required exact-release checks.

## Fail-closed boundary

Until a separate accepted record replaces the pending template:

- `goreecloud.platform.yaml` release evidence remains empty;
- no release tag, release URL, artifact digest, SBOM, signature, deployment identity, or rollback success may be inferred;
- `release-provenance-rollback` remains blocked;
- lifecycle remains Seal and deployment remains development;
- no Anchor, Stable, published-release, or `Protected by Wardveil` authority is created.

The template validator exists to prevent placeholder data from being mistaken for accepted evidence.
