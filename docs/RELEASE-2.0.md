# Wardveil Security — Version 2.0 Release Boundary

**Internal Version:** 2.0.0  
**External Version:** 2.0.0  
**Version Name:** None  
**Lifecycle:** Seal  
**Deployment State:** Development  
**Qualification State:** Blocked  
**Exact Candidate:** `wardveil-2.0.0-seal.1`  
**Frozen Implementation Source:** `cc493530c02925a4404c54d2767c15d9fbfa0835`  
**Successor Development Line:** 2.0.1

## Bounded 2.0 scope

Version 2.0 packages the implementation already frozen and source-validated as the Wardveil Seal candidate. The version rebaseline does not add unverified behavior and does not convert source validation into production acceptance, a `Protected by Wardveil` claim, or Anchor/Stable authority.

The authoritative current implemented scope is `docs/IMPLEMENTED-FEATURES.md`. Historical Foundation 0.9 wording remains implementation provenance for the frozen source.

## Non-deferrable 2.0 Anchor gates

The nine gate groups in `qualification/seal-readiness.json` remain attached to Version 2.0. They may not be moved to 2.0.1 merely to obtain a Stable label. Anchor/Stable promotion requires those gates to pass for the exact 2.0 candidate, including applicable production identity/key custody, platform-system acceptance, target-runtime evidence, Everkeep recovery, consequential-execution readback, observability/monitoring, current Glaze acceptance for shipped UI, release provenance/rollback, and public-history safety.

## Version 2.0.1

Version 2.0.1 owns unfinished or unverified **feature expansion** outside the bounded 2.0 release and outside the mandatory 2.0 Anchor gates. The detailed successor scope is maintained in `docs/PLANNED-FEATURES.md`.

2.0.1 is not part of the 2.0 candidate and receives no production or Anchor authority from 2.0.
