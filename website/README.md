# Wardveil Security Public Website

> **Static website source authority:** the canonical source for the current GoreeCloud Security route is `GoreeCloud/static-websites/sites/main/security/index.html`. This `website/` directory is a protected legacy/transitional deployment copy for the historical `security.goreecloud.com` path. Future authoritative public-site source changes belong in the centralized repository. Do not remove this copy until the legacy custom-domain/source disposition and exact production verification have passed.

The canonical GoreeCloud Security route is `https://www.goreecloud.com/security/`. The historical custom-domain path `https://security.goreecloud.com` remains a separate legacy deployment/cutover obligation until explicitly retired or redirected and verified.

## Current presentation boundary

The canonical Security Center source in `GoreeCloud/static-websites/sites/main/security/index.html` now targets **Glaze V1.7 / 1.7.0 Stable** at exact static-websites revision `531744f2a82133caca8ddde00fa782415d1a42e1`. Its consumer state is `source-adopted-unaccepted`.

For that exact central revision, repository/site validation and the Cloudflare Pages deployment check are successful. The canonical Security route blob is `1c3f93866eb76c9ce366ba8f2db42b15dc5ad427`.

This retained Wardveil `website/` directory remains a **legacy/transitional V1.6 source/build copy** for the historical `security.goreecloud.com` deployment contract. It must not be relabeled as V1.7 unless those legacy bytes are actually migrated and independently accepted.

Glaze remains presentation authority only. V1.7 source adoption, a successful build, or a deployment check cannot create, upgrade, or infer Wardveil protection, verification, response, runtime, scanner, production, Anchor, or Stable state.

Exact-current rendered/human review, accessibility, representative performance/resilience, rollback evidence, canonical deployed-byte readback, legacy custom-domain cutover/retirement, and final Security Center consumer acceptance remain open.

## Current legacy Cloudflare Pages contract

Until the controlled deployment cutover is completed, production still uses this legacy contract:

- Repository: `GoreeCloud/goreecloud-wardveil-security`
- Production branch: `main`
- Root directory: repository root
- Build command: `python3 website/build.py`
- Build output directory: `website/dist`
- Custom domain: `security.goreecloud.com`

The current source authority is `GoreeCloud/static-websites/sites/main/security/index.html`. Any remaining custom-domain/root/build retirement or redirect for this legacy copy must be verified through authenticated deployment controls rather than inferred from source documentation.

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

The centralized package has exact-revision validation in `GoreeCloud/static-websites`; revision `531744f2a82133caca8ddde00fa782415d1a42e1` passed repository/main-site validation and Cloudflare Pages deployment.

## Public-information and acceptance boundary

Wardveil Security runtime, contracts, security authority, and canonical product identity remain authoritative in this repository. **Static public website source authority does not.** The public-site source package is governed from `GoreeCloud/static-websites/sites/main/security/index.html`.

The retained legacy website source and generated `website/dist` may continue serving deployment/rollback needs only until the Cloudflare Pages project is cut over and the exact resulting production deployment is accepted. Generated output is deployment evidence, not canonical source authority.

A successful source validation, build, or preview does not independently authorize a protection claim or prove the central-source deployment cutover. Source acceptance, deployed website acceptance, runtime acceptance, scanner acceptance, and product-specific protection acceptance remain separate evidence gates.
