# Wardveil Security Public Website

This directory contains the source for the public Wardveil Security website at `https://security.goreecloud.com`.

## Cloudflare Pages contract

- Repository: `GoreeCloud/goreecloud-wardveil-security`
- Production branch: `main`
- Root directory: repository root
- Build command: `python3 website/build.py`
- Build output directory: `website/dist`
- Custom domain: `security.goreecloud.com`

The build copies the approved Wardveil identity from `branding/wardveil-security-icon.svg` into the isolated public artifact. That local file is a synchronized derivative of the canonical `GoreeCloud/goreecloud-branding-assets` source and must remain byte-identical to the approved canonical asset.

The standalone **Sentinel Fold** emblem is the owner-approved primary Wardveil Security mark. `Wardveil Security`, `Security Center`, and `by GoreeCloud` text are supporting identity/context and are not part of the emblem itself. The public site must not redraw or construct an independent Wardveil mark.

## Current public scope

The public Security Center reflects Wardveil Foundation 0.9 and may describe the accepted source architecture for Wardveil Trust, Policy, Protect, Detect, Scan, Quarantine, Response, Audit, Security Center, runtime authorization, durable execution safety, and bounded platform relationships.

ClamAV may be described only as Wardveil Scan's initial replaceable signature-based malware engine. The website must preserve the current fail-closed production boundary: source integration, scanner health, or branding alone does not establish deployed antivirus acceptance or a broad `Protected by Wardveil` claim.

## Validation

Run:

```bash
python3 website/validate.py
```

The validator checks the current machine-readable identity contract and `VERSION`, requires approved visual/showcase state, verifies byte-identical canonical icon publication, requires current Foundation and Sentinel Fold public identity language, enforces evidence-backed security wording, and checks the hardened Cloudflare Pages header contract.

## Public-information boundary

The website may present identity, public-safe first-party security architecture, normalized state semantics, evidence and authority boundaries, bounded platform relationships, malware-engine role, and private reporting guidance. It must not expose internal topology, private hostnames or addresses, credentials, tokens, signing material, unrestricted diagnostics, sensitive monitoring evidence, private vulnerability details, or other operational information unnecessary for public understanding.

Only `website/dist` is intended for Pages publication. Source acceptance, Cloudflare deployment, runtime acceptance, and product-specific protection acceptance remain separate evidence gates.