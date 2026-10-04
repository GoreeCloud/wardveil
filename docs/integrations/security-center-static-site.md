# Security Center — Current Static-Site and Glaze Authority

**Status:** Glaze V1.7 canonical source adoption complete; downstream acceptance and legacy cutover remain blocked  
**Security authority:** Wardveil Security  
**Canonical static-site repository:** `GoreeCloud/static-websites`  
**Canonical Security route:** `https://www.goreecloud.com/security/`  
**Canonical source path:** `sites/main/security/index.html`  
**Current Glaze consumer target:** Glaze V1.7 / `1.7.0`

## Current source authority

The current GoreeCloud public-web authority is the single retained website in `GoreeCloud/static-websites`. Its `sites/main/security/index.html` route is the canonical public Security Center source.

At exact static-websites revision `531744f2a82133caca8ddde00fa782415d1a42e1`, the canonical Security route declares:

- `data-glaze-version="1.7.0"`;
- `goreecloud-glaze-ui=1.7.0`;
- consumer state `source-adopted-unaccepted`;
- the canonical Wardveil Security identity; and
- explicit separation between Wardveil security authority and presentation state.

The exact Security route blob at that revision is `1c3f93866eb76c9ce366ba8f2db42b15dc5ad427`.

This completes the **canonical source-migration** portion of the Security Center Glaze V1.7 requirement. It does not establish current consumer acceptance, canonical deployed-byte equivalence, legacy custom-domain/source retirement, Wardveil runtime acceptance, Anchor qualification, or Stable status.

## Exact Glaze authority

The canonical website source lock at the same static-websites revision binds:

- Glaze version `1.7.0`;
- canonical repository `GoreeCloud/glaze`;
- bounded Stable/Anchor authority revision `1a5756daed2294155be2e9972b24f580f6222b7b`;
- Stable runtime entrypoint `js/glaze-v1.7.0.mjs`;
- entrypoint blob `c669d9c6f1738b2a56cb02b2e00fa0ca229117c0`; and
- website consumer state `source-adopted-unaccepted`.

Glaze V1.7.0 intentionally inherits the accepted V1.6.0 runtime surface. That compatibility choice does not transfer downstream Security Center acceptance.

## Current machine and deployment evidence

Static-websites PR #132 merged the V1.7 source migration as `531744f2a82133caca8ddde00fa782415d1a42e1`.

For that exact revision:

- repository validation run `37171153953` passed;
- main website validation run `37171153974` passed;
- the isolated retained-site artifact validated at 100 files / 322713 bytes;
- headless Chrome smoke passed all eleven canonical pages, including `/security/`, at desktop, tablet, modern-phone, and narrow-phone widths;
- Cloudflare Pages check `111344235579` passed for the exact revision; and
- Cloudflare Pages reported deployment id `833c933e-f6d0-48ce-b14d-30c8e62a74f2`.

The canonical website V1.7 consumer record remains unaccepted. Canonical-origin exact-byte readback, the remaining acceptance review lanes, representative performance/resilience, rollback verification, and owner production acceptance remain pending.

## Legacy Wardveil website copy

`GoreeCloud/wardveil/website` is a protected legacy/transitional deployment copy. Its active local build remains the historical Glaze UI V1.6 / `1.6.0` source mapping and must not be relabeled as V1.7 without actually rebuilding and accepting those bytes.

The legacy custom-domain path `https://security.goreecloud.com` therefore remains a separate retirement/cutover obligation. Source in the legacy copy, generated `website/dist`, centralized source, Cloudflare deployment state, canonical-domain bytes, and human consumer acceptance remain separate evidence classes.

## Qualification effect

Wardveil Version 2.0 gate `security-center-glaze-acceptance` remains **blocked**.

The missing work is no longer canonical V1.7 source adoption. Remaining work includes exact-current consumer review, canonical deployed-byte/readback evidence, representative accessibility/performance/resilience, rollback verification, legacy custom-domain/source disposition, consumer-registry/release evidence where required, and final production consumer acceptance.

## Authority boundary

Glaze is presentation authority only. A source migration, successful build, browser smoke, deployment check, or rendered page cannot create or upgrade Wardveil security state, prove a control executed, authorize a `Protected by Wardveil` claim, or establish Wardveil production acceptance.
