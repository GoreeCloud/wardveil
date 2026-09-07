# Wardveil Security Public Website

> **Static website source authority:** the canonical source for the public Security Center is now `GoreeCloud/goreecloud-static-websites/sites/security`. This `website/` directory is a protected transitional deployment copy while Cloudflare Pages still uses the legacy Wardveil repository. Future authoritative public-site source changes belong in the centralized repository. Do not remove this copy until Cloudflare repository/root/build cutover and exact production verification have passed.

The public Wardveil Security Center is `https://security.goreecloud.com`.

## Current presentation boundary

The Security Center targets **GLAZE UI V1.1 / 1.1.0 Stable** for its active public presentation layer. The current adoption preserves bounded Soft Glaze for navigation chrome, solid content and consequential security-reading surfaces, 48 px interaction targets, 56 px Touch Assistance targets, explicit Light/Dark/Deep Dark appearance mapping, safe-area handling, reduced-motion and reduced-transparency behavior, increased-contrast and forced-colors fallbacks, no-backdrop resilience, and print behavior. These presentation changes do not create, upgrade, or infer Wardveil protection, verification, response, runtime, scanner, production, or acceptance state.

GLAZE UI V1.2 Frosted Neutral remains Candidate-only and is not the active production consumer target. Earlier Glaze UI 2.x adoption records and assets are retained only as historical pre-reset evidence and are excluded from the active legacy Pages build.

## Current legacy Cloudflare Pages contract

Until the controlled deployment cutover is completed, production still uses this legacy contract:

- Repository: `GoreeCloud/goreecloud-wardveil-security`
- Production branch: `main`
- Root directory: repository root
- Build command: `python3 website/build.py`
- Build output directory: `website/dist`
- Custom domain: `security.goreecloud.com`

The target source authority after cutover is `GoreeCloud/goreecloud-static-websites/sites/security`; the final Pages root/build configuration must be verified through authenticated Cloudflare controls rather than inferred from source documentation.

The legacy build copies the approved Wardveil identity from `branding/wardveil-security-icon.svg` into the isolated public artifact. That local file is a synchronized derivative of the canonical `GoreeCloud/goreecloud-branding-assets` source and must remain byte-identical to the approved canonical asset.

The standalone **Sentinel Fold** emblem is the owner-approved primary Wardveil Security mark. `Wardveil Security`, `Security Center`, and `by GoreeCloud` text are supporting identity/context and are not part of the emblem itself. The public site must not redraw or construct an independent Wardveil mark.

## Current public scope

The public Security Center reflects Wardveil Foundation 0.9 and may describe the accepted source architecture for Wardveil Trust, Policy, Protect, Detect, Scan, Quarantine, Response, Audit, Security Center, runtime authorization, durable execution safety, and bounded platform relationships.

ClamAV may be described only as Wardveil Scan's initial replaceable signature-based malware engine. The website must preserve the current fail-closed production boundary: source integration, scanner health, or branding alone does not establish deployed antivirus acceptance or a broad `Protected by Wardveil` claim.

## Validation

Legacy-repository validation remains available while this deployment source is active:

```bash
python3 website/validate.py
python3 website/validate_responsive.py
python3 website/browser_responsive_smoke.py
```

The centralized package has its own exact-candidate validation in `GoreeCloud/goreecloud-static-websites` and has reached `validated-in-central-repo`.

## Public-information and acceptance boundary

Wardveil Security runtime, contracts, security authority, and canonical product identity remain authoritative in this repository. **Static public website source authority does not.** The public-site source package is governed from `GoreeCloud/goreecloud-static-websites/sites/security`.

The retained legacy website source and generated `website/dist` may continue serving deployment/rollback needs only until the Cloudflare Pages project is cut over and the exact resulting production deployment is accepted. Generated output is deployment evidence, not canonical source authority.

A successful source validation, build, or preview does not independently authorize a protection claim or prove the central-source deployment cutover. Source acceptance, deployed website acceptance, runtime acceptance, scanner acceptance, and product-specific protection acceptance remain separate evidence gates.
