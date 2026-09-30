# GoreeCloud Policy v1 Integration — Wardveil Security

**Status:** Weave source adoption only. Live Policy runtime acceptance remains incomplete.

Wardveil consumes the authoritative GoreeCloud Policy v1 request/decision contracts at repository revision `46071886da37a6566b69cc923005eef64cce2bcc`.

## Authority boundary

GoreeCloud Policy does not replace Wardveil security-domain policy semantics. Shared Policy decisions may contribute bounded decision evidence and constraints to Wardveil workflows, but Wardveil remains responsible for its security-domain rules within its authority.

A Policy allow is not Wardveil execution authorization. It does not prove a target action ran, create Protected/Covered status, satisfy target-side authorization, execute obligations, or grant production acceptance.

The source adapter:

- constructs the exact Policy v1 evaluation-request shape;
- recursively rejects obvious credentials, secrets, private content, and sensitive context keys;
- validates the complete six-value decision vocabulary and exact decision shape;
- optionally binds returned evidence to the exact expected request;
- requires timezone-qualified decision timestamps;
- exposes stale decisions as unusable evidence; and
- fixes execution/protection/production authority to false.

Source adoption does not establish live Policy runtime acceptance. Production acceptance still requires authenticated caller identity, approved transport, decision freshness/expiry handling, policy distribution where applicable, obligations coordination, target-environment evidence, recovery behavior, and exact release qualification.
