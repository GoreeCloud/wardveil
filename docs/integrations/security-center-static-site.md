# Security Center — Current Static-Site and Glaze Authority

**Status:** Glaze V1.7 machine/deployment/readback evidence complete; human consumer acceptance remains blocked  
**Security authority:** Wardveil Security  
**Canonical static-site repository:** `GoreeCloud/static-websites`  
**Canonical Security route:** `https://www.goreecloud.com/security/`  
**Current Glaze consumer target:** Glaze V1.7 / `1.7.0`

## Current source authority

The current GoreeCloud public-web authority is `GoreeCloud/static-websites`. The canonical Security Center source is:

`sites/main/security/index.html`

The exact deployed/readback candidate is static-websites revision `17303b6c7381faaa0e89ce6175ce24048fb56a12`. Its Security route blob is:

`f3d6cac2b16954e0879298de0724bfe16b916715`

Current static-websites `main` is `9ae21cf12e276ea7e553fcf2573318602886428e`. Later support-documentation/test-restoration changes did not change public artifact bytes; the Security route blob on current `main` remains byte-identical to the deployed/readback candidate.

The route declares Glaze `1.7.0` and consumer state `source-adopted-unaccepted`.

## Exact Glaze authority

The shared website lock binds:

- canonical Glaze repository `GoreeCloud/glaze`;
- version `1.7.0`;
- Stable authority revision `1a5756daed2294155be2e9972b24f580f6222b7b`;
- entrypoint `js/glaze-v1.7.0.mjs`;
- entrypoint blob `c669d9c6f1738b2a56cb02b2e00fa0ca229117c0`; and
- Stable runtime baseline `1.6.0`.

Glaze presentation authority does not transfer Wardveil runtime, execution, protection, production, Anchor, or Stable authority.

## Machine and canonical deployment evidence

The authoritative Glaze V1.7 website consumer record on current static-websites `main` is `pending-human-acceptance`, not fully accepted.

For exact deployed/readback candidate `17303b6c7381faaa0e89ce6175ce24048fb56a12`:

- repository validation passed;
- main-site validation passed;
- isolated public artifact validation passed;
- responsive/interaction Chrome smoke passed;
- privacy/security public-surface validation passed;
- all eleven canonical HTML routes matched production byte-for-byte;
- total compared canonical HTML was 115,559 bytes;
- the current 404 body plus Glaze and Mesh SVG assets also matched exact source bytes; and
- production evidence is recorded as `deployed-readback-verified`.

For Security Center specifically, `/security/` matched `sites/main/security/index.html` exactly at 9,953 bytes.

## Remaining consumer-acceptance work

The shared website consumer record still requires:

- owner visual review;
- keyboard-only review;
- representative assistive-technology review;
- representative performance/resilience acceptance; and
- final owner production consumer approval.

The website rollback record already identifies Glaze V1.6 as the last-known-good presentation baseline and verifies independent source reversibility through Git history. Product-specific legacy deployment cleanup remains separate.

## Legacy Wardveil website copy

`GoreeCloud/wardveil/website` remains a protected legacy/transitional V1.6 deployment package associated with the historical `security.goreecloud.com` path.

It must not be relabeled as current Glaze V1.7 source. Retirement, redirect, or cutover of the legacy custom-domain/source path requires its own verified deployment action.

## Qualification effect

Wardveil Version 2.0 gate `security-center-glaze-acceptance` remains **blocked**, but canonical source migration, exact machine validation, deployment, and canonical readback are no longer missing.

Remaining blockers are the shared website human/performance consumer-acceptance lanes, final owner consumer approval, and the Wardveil-specific legacy `security.goreecloud.com` retirement/cutover obligation.

No `Protected by Wardveil` claim, runtime acceptance, production acceptance, Anchor promotion, or Stable status is created by website evidence.
