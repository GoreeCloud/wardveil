# Wardveil Security Center — Glaze V1.7 Source Adoption Evidence

**Status:** Canonical source adoption complete; consumer acceptance remains blocked  
**Canonical website repository:** `GoreeCloud/static-websites`  
**Canonical Security Center route:** `https://www.goreecloud.com/security/`  
**Canonical source revision:** `531744f2a82133caca8ddde00fa782415d1a42e1`  
**Canonical route blob:** `1c3f93866eb76c9ce366ba8f2db42b15dc5ad427`  
**Glaze target:** V1.7 / `1.7.0`

## Current source authority

The public GoreeCloud website is the canonical source authority for the current Security Center route. The authoritative source is:

`GoreeCloud/static-websites/sites/main/security/index.html`

At revision `531744f2a82133caca8ddde00fa782415d1a42e1`, that route declares:

- `data-glaze-version="1.7.0"`;
- `goreecloud-glaze-ui=1.7.0`;
- consumer state `source-adopted-unaccepted`;
- Wardveil Security as the security/protection authority; and
- explicit separation between presentation state and actual protection evidence.

The shared website lock at that revision binds Glaze Stable authority to:

- repository `GoreeCloud/glaze`;
- version `1.7.0`;
- Stable revision `1a5756daed2294155be2e9972b24f580f6222b7b`;
- entrypoint `js/glaze-v1.7.0.mjs`;
- entrypoint blob `c669d9c6f1738b2a56cb02b2e00fa0ca229117c0`;
- Stable runtime baseline `1.6.0`; and
- consumer state `source-adopted-unaccepted`.

Glaze V1.7.0 intentionally inherits the accepted V1.6.0 runtime surface. That compatibility boundary supports source adoption without transferring downstream acceptance.

## Current validation and deployment evidence

For exact static-websites revision `531744f2a82133caca8ddde00fa782415d1a42e1`:

- repository validation passed;
- retained-public-site validation passed;
- the canonical website source/build/browser validation passed;
- Cloudflare Pages check `111350809391` completed successfully; and
- the successful Pages preview is `https://3f1561c8.goreecloud-website.pages.dev`.

This establishes canonical source adoption and a successful Pages deployment check for the shared website revision.

It does **not** establish exact canonical-domain byte readback for `https://www.goreecloud.com/security/` or `https://security.goreecloud.com/`, final human visual/accessibility acceptance, representative performance/resilience acceptance, exact rollback exercise, legacy custom-domain cutover/retirement, or final Security Center consumer approval.

## Legacy Wardveil website copy

`GoreeCloud/wardveil/website` is a protected transitional deployment copy. Its historical Glaze V1.6 source/build mapping remains useful rollback/deployment provenance while the legacy `security.goreecloud.com` Pages contract exists.

The legacy copy must not be relabeled as a V1.7 implementation unless its own bytes are actually migrated and accepted. Its stale README authority wording is corrected to point to `GoreeCloud/static-websites`, but the legacy V1.6 source itself remains historical/transitional until cutover or retirement.

## Qualification effect

The **source-migration** portion of Wardveil Version 2.0 gate `security-center-glaze-acceptance` is complete because the canonical Security Center source now targets Glaze V1.7 / 1.7.0.

The gate remains **blocked** until exact-current consumer acceptance is complete, including applicable rendered/human review, accessibility, representative performance/resilience, rollback, canonical deployed-byte/readback evidence, legacy deployment cutover/retirement, and production consumer acceptance.

## Authority boundary

Glaze is presentation authority only. A V1.7 source target, successful build, successful deployment check, favorable rendering, or consumer record cannot create a Wardveil protection claim, execution result, runtime acceptance, production acceptance, Anchor promotion, or Stable status.
