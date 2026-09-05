# Wardveil Security Public Website

This directory contains the source for the public Wardveil Security Center at `https://security.goreecloud.com`.

## Current presentation boundary

The Security Center targets **GLAZE UI V1.1 / 1.1.0 Stable** for its active public presentation layer. The current adoption preserves bounded Soft Glaze for navigation chrome, solid content and consequential security-reading surfaces, 48 px interaction targets, 56 px Touch Assistance targets, explicit Light/Dark/Deep Dark appearance mapping, safe-area handling, reduced-motion and reduced-transparency behavior, increased-contrast and forced-colors fallbacks, no-backdrop resilience, and print behavior. These presentation changes do not create, upgrade, or infer Wardveil protection, verification, response, runtime, scanner, production, or acceptance state.

GLAZE UI V1.2 Frosted Neutral remains Candidate-only and is not the active production consumer target. Earlier Glaze UI 2.x adoption records and assets are retained only as historical pre-reset evidence and are excluded from the active Pages build.

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
python3 website/validate_responsive.py
python3 website/browser_responsive_smoke.py
```

The validator checks the current machine-readable identity contract and `VERSION`, requires approved visual/showcase state, verifies byte-identical canonical icon publication, requires current Foundation and Sentinel Fold public identity language, enforces evidence-backed security wording, checks the exact GLAZE UI V1.1 Stable presentation target and historical-target isolation, and validates the hardened Cloudflare Pages header contract. Responsive source and Chrome geometry gates independently protect 1180, 768, 390, and 320 px-class layouts.

## Public-information and acceptance boundary

The website may present identity, public-safe first-party security architecture, normalized state semantics, evidence and authority boundaries, bounded platform relationships, malware-engine role, and private reporting guidance. It must not expose internal topology, private hostnames or addresses, credentials, tokens, signing material, unrestricted diagnostics, sensitive monitoring evidence, private vulnerability details, or other operational information unnecessary for public understanding.

Only `website/dist` is intended for Pages publication. A successful source validation, build, or preview does not independently authorize a protection claim. The exact candidate revision must pass the applicable branch-preview/deployment verification before merge, and the resulting `main` revision must be verified on `security.goreecloud.com` after deployment. Source acceptance, deployed website acceptance, runtime acceptance, scanner acceptance, and product-specific protection acceptance remain separate evidence gates.
