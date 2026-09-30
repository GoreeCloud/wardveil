# Security Policy

Wardveil Security is GoreeCloud’s platform-wide security and protection authority and shared security plane. This repository contains Development source, contracts, reference implementations, validation, and supporting security controls; none of those artifacts alone proves platform-wide production protection. This repository must not become a storage location for production credentials, reusable secrets, private security evidence, or unrestricted operational exports.

## Reporting

Security-sensitive findings should be handled through a private GoreeCloud administrative channel or GitHub private security reporting when available. Do not place active credentials, private keys, API tokens, recovery codes, session material, or exploit-sensitive private infrastructure details in a public issue or pull request.

If a public issue is sufficient to describe a problem, sanitize it first and include only the minimum information required to reproduce or understand the defect.

## Repository security boundary

This repository may contain:

- public or internal identity contracts;
- normalized status schemas;
- non-sensitive examples;
- validators and conformance rules;
- presentation and integration guidance.

It must not contain:

- passwords or passphrases;
- private keys or private certificate keys;
- API keys, access tokens, refresh tokens, or setup keys;
- recovery codes or multifactor seeds;
- session cookies or session-signing secrets;
- production `.env` files;
- unrestricted security logs or raw diagnostic exports containing private data;
- detailed operational evidence that creates unnecessary exposure.

## Status and evidence handling

Wardveil-facing records must remain data-minimized. The authoritative security system should retain detailed evidence when required; Wardveil integrations should normally receive only the bounded status, source attribution, timestamps, sanitized summary, and authorized action metadata necessary for presentation.

Missing or stale evidence must fail closed to a non-passing presentation state. Wardveil branding, icons, labels, or metadata are never evidence that an underlying control succeeded.

## Canonical identity boundary

The approved Wardveil Security identity is governed by `GoreeCloud/goreecloud-branding-assets`, with the canonical system asset under `systems/wardveil-security/wardveil-security-icon.svg`. The repository-local `branding/wardveil-security-icon.svg` is a synchronized consumer derivative for Wardveil-owned use and must remain traceable to the approved authority. Branding identifies Wardveil but never proves technical protection, coverage, runtime acceptance, or production readiness.

## Changes affecting security semantics

Changes to any of the following require explicit review and validation:

- approved Wardveil naming;
- technical-authority boundaries;
- protection-claim rules;
- normalized security states;
- status/evidence schema semantics;
- privacy and redaction requirements;
- canonical icon and showcase gates;
- legal/public-release status.
