# Wardveil Persistence Service-Binding RPC API v1

**API version:** `wardveil-persistence-rpc/v1`  
**Transport:** private Cloudflare service-binding RPC  
**Canonical binding:** `WARDVEIL_PERSISTENCE`  
**Public HTTP:** liveness/readiness only at `/healthz` and `/readyz`

## Purpose

The Wardveil Cloudflare persistence runtime already exposes a private first-party RPC surface used by Wardveil components and acceptance probes. This document makes that existing interface explicit and versioned for Platform Contract and release-readiness governance.

The API is not a public mutation API. Applications do not gain direct database authority by knowing the method names.

## Runtime operations

The v1 private RPC surface consists of:

- `append` — append one bounded Wardveil record for an authorized tenant.
- `readAfter` — read bounded ordered records after a sequence.
- `checkpoint` / `getCheckpoint` — maintain monotonic consumer checkpoints.
- `claimExecutionAuthorization` — durably claim an exact high-impact execution authorization before side effects.
- `finalizeExecutionAuthorization` — persist the authoritative final execution receipt.
- `getExecutionReceipt` — retrieve the durable execution outcome for exact replay/reconciliation handling.
- `maintenanceEvidence` — retrieve bounded maintenance evidence.
- `health` — read privacy-safe storage/schema/recovery health used by internal acceptance and public readiness.

The acceptance-only operations `scheduleAcceptanceRetentionAlarm` and `emitAcceptanceObservabilityFailure` exist solely for controlled runtime qualification. They are not ordinary product mutation capabilities.

## Authority and security boundary

All mutation-capable RPC calls require the caller to arrive through a configured private service binding and the operation-specific Wardveil authorization boundary. The API does not transfer target-system authority, security-state authority, protection-claim authority, Privacy Shield authority, or Everkeep recovery authority.

Public HTTP remains bounded to non-mutating liveness/readiness. A generic public record, checkpoint, execution, or acceptance mutation route is prohibited.

## Versioning and compatibility

The Platform Contract declares this interface as `wardveil-persistence-rpc/v1`. Incompatible field, method, authority, replay, retention, or execution semantics require an explicit new API version and migration evidence. Source compatibility does not establish deployed runtime acceptance.

## Acceptance boundary

A documented/versioned API does not prove production deployment, caller authentication, service-binding configuration, operational capacity, recovery, or a Protected-by-Wardveil claim. Exact deployed evidence remains required independently.
