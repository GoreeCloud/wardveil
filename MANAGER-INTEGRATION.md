# GoreeCloud Manager Integration — Wardveil Security

**Status:** Weave source adoption. Live authenticated delivery and production acceptance remain incomplete.

GoreeCloud Manager already contains a bounded read-only consumer for Wardveil Security State v2. Manager main `ebf5ea526c14a198ebaabf76fe923e82bddd2ad6` pins Wardveil contract revision `9b41040ed48037451e660e860908316732384282`.

The pinned Manager contract blob is byte-identical to the current Wardveil `contracts/wardveil.security-state.v2.schema.json` blob. Wardveil's current producer/reference path remains `reference/wardveil_security_state_v2.py`.

## Authority boundary

Manager is a read-only administrative consumer. It does not become authoritative for Wardveil security state, protection coverage, Trust, Policy, Protect, Detect, Scan, Quarantine, Response, or Audit.

A valid Security State v2 record does not by itself prove authenticated producer identity, protected transport, live freshness, production coverage, or execution success.

Wardveil does not gain Manager administrative authority by supplying status evidence.

## Source evidence

The Wardveil Security State v2 producer:

- binds state and coverage to exact scope;
- preserves explicit unknown, not-covered, stale, degraded, contained, recovering, and reconciliation-required states;
- requires production-accepted coverage plus current content-addressed evidence before a Protected claim;
- rejects conflicting or foreign-scope evidence; and
- keeps state presentation separate from action execution authority.

## Remaining acceptance

The Manager integration remains migration-required until there is accepted authenticated Wardveil producer identity, approved delivery/refresh, target-environment validation, Manager fault isolation and operational evidence for the live path, production acceptance, exact release qualification, and applicable recovery/rollback evidence.
